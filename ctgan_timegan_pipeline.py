# ctgan_timegan_pipeline.py
import os, json, numpy as np, pandas as pd, yaml, time
from typing import List, Tuple, Dict

from sdv.single_table import CTGANSynthesizer
from sdv.metadata import SingleTableMetadata

import tensorflow as tf
from tensorflow.keras import layers, Model
from tensorflow.keras.optimizers import Adam

# --------------------------
# Utils
# --------------------------
def set_seed(seed=42):
    import random
    np.random.seed(seed); tf.random.set_seed(seed); random.seed(seed)

set_seed(42)

def minmax_scale_3d(x):
    # x: (n, t, f)
    eps = 1e-8
    x_min = x.min(axis=(0,1), keepdims=True)
    x_max = x.max(axis=(0,1), keepdims=True)
    scaled = (x - x_min) / (x_max - x_min + eps)
    return scaled.astype('float32'), (x_min, x_max)

def minmax_inverse_3d(x_scaled, scaler_params):
    x_min, x_max = scaler_params
    return x_scaled * (x_max - x_min + 1e-8) + x_min

# --------------------------
# Load Dataset
# --------------------------
def load_unsw(path='UNSW_NB15_training-set.csv'):
    if os.path.exists(path):
        df = pd.read_csv(path)
    else:
        n = 10000
        df = pd.DataFrame({
            'proto': np.random.choice(['tcp','udp','icmp'],n, p=[0.6,0.35,0.05]),
            'service': np.random.choice(['http','ssh','ftp','dns','smtp','telnet','imap','pop3','https','snmp'], n),
            'state': np.random.choice(['CON','FIN','REQ','RST'], n, p=[0.55,0.1,0.25,0.1]),
            'spkts': np.random.exponential(10, n).astype(int),
            'dpkts': np.random.exponential(8, n).astype(int),
            'sbytes': np.random.exponential(1200, n).astype(int),
            'dbytes': np.random.exponential(900, n).astype(int),
            'ct_src_dport_ltm': np.random.randint(0, 20, n),
            'ct_dst_sport_ltm': np.random.randint(0, 20, n),
            'timestamp': np.linspace(0, 100000, n).astype(int),
        })
    return df

# --------------------------
# Build sequences
# --------------------------
def build_sequences(df, seq_len=32, feature_cols=None, step=8):
    if feature_cols is None:
        numeric = df.select_dtypes(include=[np.number]).columns.tolist()
        # prioritize packet/byte counts
        priority = [c for c in ['spkts','dpkts','sbytes','dbytes','ct_src_dport_ltm','ct_dst_sport_ltm'] if c in df.columns]
        rest = [c for c in numeric if c not in priority and c != 'timestamp']
        feature_cols = priority + rest[:max(0, 8-len(priority))]
    arr = df[feature_cols].fillna(0).values
    seqs = []
    for i in range(0, len(arr)-seq_len+1, step):
        seqs.append(arr[i:i+seq_len])
    seqs = np.array(seqs).astype('float32')
    return seqs, feature_cols

# --------------------------
# CTGAN Training with tuning
# --------------------------
def train_ctgan(df, ctgan_cols, epochs=800, sample_n=1000, save_path='ctgan_configs.json',
                condition_col=None, condition_values=None, batch_size=500, pac=10):
    assert batch_size % pac == 0, f"batch_size ({batch_size}) must be divisible by pac ({pac})"
    df_ct = df.copy()
    available = [c for c in ctgan_cols if c in df_ct.columns]
    df_ct = df_ct[available].copy()
    # simple NA handling
    for c in df_ct.columns:
        if df_ct[c].dtype == 'object':
            df_ct[c] = df_ct[c].fillna('NA').astype(str)
        else:
            df_ct[c] = df_ct[c].fillna(0)

    metadata = SingleTableMetadata()
    metadata.detect_from_dataframe(data=df_ct)
    if metadata.primary_key in available:
        metadata.primary_key = None

    # Tuning per SDV/CTGAN tips: larger nets, pac > 1, more epochs
    # generator_dim / discriminator_dim accept tuples of hidden sizes
    synthesizer = CTGANSynthesizer(
        metadata=metadata,
        epochs=epochs,
        batch_size=batch_size,  # Changed from 512 to 500
        generator_dim=(256, 256),
        discriminator_dim=(256, 256),
        discriminator_steps=2,
        pac=pac,          # 500 is divisible by 10
        verbose=True
    )
    synthesizer.fit(df_ct)

    samples_df_list = []
    if condition_col and condition_col in df_ct.columns and condition_values:
        for val in condition_values:
            cond = {condition_col: val}
            part = synthesizer.sample(num_rows=max(1, sample_n // len(condition_values)), conditions=cond)
            samples_df_list.append(part)
        samples_df = pd.concat(samples_df_list, ignore_index=True)
    else:
        samples_df = synthesizer.sample(num_rows=sample_n)

    samples = samples_df.to_dict(orient='records')
    with open(save_path,'w') as f:
        json.dump(samples, f, indent=2)
    # persist model for reuse
    synthesizer.save('ctgan_model.pkl')
    return samples_df

# --------------------------
# Supervised TimeGAN (Keras)
# --------------------------
class SupervisedTimeGAN:
    def __init__(self, seq_len, feature_dim, hidden_dim=64, z_dim=64, lr=1e-4):
        self.seq_len = seq_len
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.z_dim = z_dim
        self._build()
        self.opt = Adam(lr)

    def _embedder(self):
        x_in = layers.Input(shape=(self.seq_len, self.feature_dim))
        h = layers.LSTM(self.hidden_dim, return_sequences=True)(x_in)
        h = layers.LSTM(self.hidden_dim, return_sequences=True)(h)
        return x_in, Model(x_in, h, name='embedder')

    def _recovery(self):
        h_in = layers.Input(shape=(self.seq_len, self.hidden_dim))
        x_tilde = layers.LSTM(self.hidden_dim, return_sequences=True)(h_in)
        x_tilde = layers.TimeDistributed(layers.Dense(self.feature_dim, activation='sigmoid'))(x_tilde)
        return h_in, Model(h_in, x_tilde, name='recovery')

    def _generator(self):
        z_in = layers.Input(shape=(self.seq_len, self.z_dim))
        g = layers.LSTM(self.hidden_dim, return_sequences=True)(z_in)
        g = layers.LSTM(self.hidden_dim, return_sequences=True)(g)
        return z_in, Model(z_in, g, name='generator')

    def _supervisor(self):
        h_in = layers.Input(shape=(self.seq_len, self.hidden_dim))
        s = layers.LSTM(self.hidden_dim, return_sequences=True)(h_in)
        return h_in, Model(h_in, s, name='supervisor')

    def _discriminator(self):
        h_in = layers.Input(shape=(self.seq_len, self.hidden_dim))
        d = layers.LSTM(self.hidden_dim, return_sequences=False)(h_in)
        d = layers.Dense(1, activation='sigmoid')(d)
        return h_in, Model(h_in, d, name='discriminator')

    def _build(self):
        xin, self.embedder = self._embedder()
        hin, self.recovery = self._recovery()
        zin, self.generator = self._generator()
        hsin, self.supervisor = self._supervisor()
        hdin, self.discriminator = self._discriminator()

        self.x_input = xin
        self.h_input = hin
        self.z_input = zin

    def train(self, real_scaled, epochs=1500, batch_size=128):
        # Phase 1: autoencoder
        for e in range(300):
            idx = np.random.randint(0, real_scaled.shape, size=batch_size)
            x = real_scaled[idx]
            with tf.GradientTape() as tape:
                h = self.embedder(x, training=True)
                x_tilde = self.recovery(h, training=True)
                loss_ae = tf.reduce_mean(tf.losses.mse(x, x_tilde))
            vars_ae = self.embedder.trainable_variables + self.recovery.trainable_variables
            grads = tape.gradient(loss_ae, vars_ae)
            self.opt.apply_gradients(zip(grads, vars_ae))
            if e % 100 == 0:
                print(f"[TimeGAN] AE epoch {e} loss {loss_ae.numpy():.4f}")

        bce = tf.keras.losses.BinaryCrossentropy(from_logits=False)
        mse = tf.keras.losses.MeanSquaredError()

        # Phase 2+3: supervised + adversarial joint
        for e in range(epochs):
            # sample real
            idx = np.random.randint(0, real_scaled.shape, size=batch_size)
            x = real_scaled[idx]
            z = np.random.normal(size=(batch_size, self.seq_len, self.z_dim)).astype('float32')

            # supervised loss: h -> s(h) next-step prediction in latent
            with tf.GradientTape() as tape_sup:
                h = self.embedder(x, training=True)
                h_hat_supervise = self.supervisor(h, training=True)
                sup_loss = tf.reduce_mean(tf.losses.mse(h[:,1:,:], h_hat_supervise[:,:-1,:]))
            vars_sup = self.embedder.trainable_variables + self.supervisor.trainable_variables
            grads_sup = tape_sup.gradient(sup_loss, vars_sup)
            self.opt.apply_gradients(zip(grads_sup, vars_sup))

            # generator path
            with tf.GradientTape() as tape_g:
                # synthetic hidden via generator+supervisor
                e_hat = self.generator(z, training=True)
                h_hat = self.supervisor(e_hat, training=True)
                y_fake = self.discriminator(h_hat, training=True)
                g_loss_u = bce(tf.ones_like(y_fake), y_fake)
                # moment matching on features
                x_hat = self.recovery(h_hat, training=True)
                g_loss_v = mse(tf.reduce_mean(x, axis=0), tf.reduce_mean(x_hat, axis=0))
                g_loss = g_loss_u + 100 * sup_loss + 10 * g_loss_v
            vars_g = self.generator.trainable_variables + self.supervisor.trainable_variables
            grads_g = tape_g.gradient(g_loss, vars_g)
            self.opt.apply_gradients(zip(grads_g, vars_g))

            # discriminator path
            with tf.GradientTape() as tape_d:
                h_real = self.embedder(x, training=True)
                y_real = self.discriminator(h_real, training=True)
                e_hat = self.generator(z, training=True)
                h_hat = self.supervisor(e_hat, training=True)
                y_fake = self.discriminator(h_hat, training=True)
                d_loss = bce(tf.ones_like(y_real), y_real) + bce(tf.zeros_like(y_fake), y_fake)
            grads_d = tape_d.gradient(d_loss, self.discriminator.trainable_variables)
            self.opt.apply_gradients(zip(grads_d, self.discriminator.trainable_variables))

            if e % 200 == 0:
                print(f"[TimeGAN] epoch {e} sup {sup_loss.numpy():.4f} g {g_loss.numpy():.4f} d {d_loss.numpy():.4f}")

    def sample(self, n):
        z = np.random.normal(size=(n, self.seq_len, self.z_dim)).astype('float32')
        e_hat = self.generator(z, training=False)
        h_hat = self.supervisor(e_hat, training=False)
        # map back to data space
        x_hat = self.recovery(h_hat, training=False).numpy()
        return x_hat

# --------------------------
# ML Evaluations
# --------------------------
def ctgan_tstr(real_df, synth_df, cols, label_col='service'):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, f1_score
    from sklearn.model_selection import train_test_split

    real = real_df[cols].copy()
    synth = synth_df[cols].copy()

    # encode categoricals consistently
    Xr = real.drop(label_col, axis=1); yr = real[label_col]
    Xs = synth.drop(label_col, axis=1); ys = synth[label_col]

    for col in Xr.columns:
        if Xr[col].dtype == 'object' or Xs[col].dtype == 'object':
            vals = list(pd.unique(pd.concat([Xr[col].astype(str), Xs[col].astype(str)], ignore_index=True)))
            mapd = {v:i for i,v in enumerate(vals)}
            Xr[col] = Xr[col].astype(str).map(mapd)
            Xs[col] = Xs[col].astype(str).map(mapd)

    if yr.dtype == 'object' or ys.dtype == 'object':
        vals = list(pd.unique(pd.concat([yr.astype(str), ys.astype(str)], ignore_index=True)))
        mapy = {v:i for i,v in enumerate(vals)}
        yr = yr.astype(str).map(mapy)
        ys = ys.astype(str).map(mapy)

    # train on synth, test on real (stratify)
    Xs_tr, _, ys_tr, _ = train_test_split(Xs, ys, test_size=0.0, train_size=1.0, stratify=ys if ys.nunique()>1 else None)
    Xr_te, yr_te = Xr, yr

    clf = RandomForestClassifier(n_estimators=400, max_depth=None, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1, random_state=42)
    clf.fit(Xs_tr, ys_tr)
    y_pred = clf.predict(Xr_te)
    acc = accuracy_score(yr_te, y_pred)
    f1 = f1_score(yr_te, y_pred, average='weighted')
    return acc, f1

def timegan_tstr(real_seq, synth_seq):
    from sklearn.metrics import accuracy_score, f1_score
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import GradientBoostingClassifier

    # Task: classify above/below median on mean over first 2 features
    real_feat = real_seq[:,:,:2].mean(axis=(1,2))
    synth_feat = synth_seq[:,:,:2].mean(axis=(1,2))
    y_real = (real_feat > np.median(real_feat)).astype(int)
    y_synth = (synth_feat > np.median(synth_feat)).astype(int)

    X_s = synth_seq.reshape(synth_seq.shape, -1)
    X_r = real_seq.reshape(real_seq.shape, -1)

    clf = GradientBoostingClassifier(random_state=42)
    clf.fit(X_s, y_synth)
    y_pred = clf.predict(X_r)
    acc = accuracy_score(y_real, y_pred)
    f1 = f1_score(y_real, y_pred)
    return acc, f1

def timegan_discriminative(real_seq, synth_seq):
    from sklearn.metrics import accuracy_score
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier

    Xr = real_seq.reshape(real_seq.shape, -1)
    Xs = synth_seq.reshape(synth_seq.shape, -1)
    X = np.vstack([Xr, Xs])
    y = np.array([1]*len(Xr) + [0]*len(Xs))  # <-- Fixed line
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=400, max_depth=None, random_state=42, n_jobs=-1)
    clf.fit(Xtr, ytr)
    ypred = clf.predict(Xte)
    return accuracy_score(yte, ypred)

# --------------------------
# Honeyd integration helpers (TimeGAN-driven)
# --------------------------
from honeyd_config_generator import HoneydConfigGenerator

def seq_to_service_profile(seq_batch):
    # Derive per-service behavior parameters from synthetic sequences
    # e.g., request rate, response size, error probability
    # Use statistics from features 0..3 as proxy
    rates = seq_batch[:,:,0].mean(axis=1)  # spkts-like
    sizes = seq_batch[:,:,2].mean(axis=1)  # sbytes-like
    errs  = np.clip(seq_batch[:,:,1].std(axis=1) / (seq_batch[:,:,1].mean(axis=1)+1e-6), 0.0, 1.0)
    return rates, sizes, errs

def build_honeypot_metadata(ctgan_out: pd.DataFrame, honey: HoneydConfigGenerator, base_ip='10.10.10', max_hosts=20,
                            timegan_profiles=None):
    # Map many services and multiple ports
    # Expand to TCP and UDP services
    all_services = list(honey.service_ports.keys()) + ['ntp','ldap','rdp','mssql','rdp-3389','redis','memcached','mysql','postgres']
    extra_ports = {
        'ntp': 123, 'ldap':389, 'rdp':3389, 'mssql':1433, 'redis':6379, 'memcached':11211,
        'mysql':3306, 'postgres':5432, 'rdp-3389':3389
    }
    service_port_map = {**honey.service_ports, **extra_ports}

    metadata = []
    n_hosts = min(max_hosts, len(ctgan_out))
    # derive TimeGAN profiles if provided
    if timegan_profiles is not None:
        rates, sizes, errs = timegan_profiles
    else:
        rates = np.random.uniform(1,10,size=n_hosts)
        sizes = np.random.uniform(200, 2000, size=n_hosts)
        errs = np.random.uniform(0.0, 0.2, size=n_hosts)

    for i in range(n_hosts):
        cfg = ctgan_out.iloc[i].to_dict()
        # vectorization for service selection
        vec = []
        for k,v in cfg.items():
            if isinstance(v,(int,float)): vec.append(float(v))
            elif isinstance(v,str): vec.append(float(sum(map(ord,v))%100)/100.0)
            else: vec.append(0.0)
        while len(vec) < 64: vec.append(0.0)
        vec = np.array(vec[:64])

        # choose 6-10 services per host based on vec top-k
        vn = (vec - vec.min()) / (vec.max()-vec.min() + 1e-8)
        top_idx = np.argsort(-vn)[:10]
        chosen = []
        for idx in top_idx:
            svc = all_services[idx % len(all_services)]
            if svc not in chosen:
                chosen.append(svc)
            if len(chosen) >= np.random.randint(6,11):
                break
        if 'http' not in chosen:
            chosen = 'http'
        # build service meta with scripts and banners
        service_meta = []
        for svc in chosen:
            port = service_port_map.get(svc, 10000 + (hash(svc) % 50000))
            banner = honey.get_banner(svc)
            script_path = f'honeypot_scripts/{svc}_script.py'
            service_meta.append({
                'name': svc,
                'port': int(port),
                'banner': banner,
                'script': script_path,
                # attach TimeGAN-driven behavior
                'rate': float(rates[i % len(rates)]),
                'avg_size': float(sizes[i % len(sizes)]),
                'err_prob': float(errs[i % len(errs)])
            })

        ip = f'{base_ip}.{10+i}'
        os_type = np.random.choice(honey.os_templates)
        metadata.append({
            'ip': ip,
            'os': os_type,
            'template': f'template{i}',
            'services': service_meta,
            # Honeyd realism knobs (user can apply in generator)
            'droprate_in': float(np.clip(errs[i % len(errs)]*0.2,0,0.3)),
            'droprate_syn': float(np.clip(errs[i % len(errs)]*0.1,0,0.2))
        })
    return metadata

# --------------------------
# Main
# --------------------------
def main():
    set_seed(42)
    df = load_unsw()

    # Columns for CTGAN
    ctgan_cols = ['proto','service','state','spkts','dpkts','sbytes','dbytes','ct_src_dport_ltm','ct_dst_sport_ltm']
    # Train CTGAN with conditional sampling to balance services if available
    condition_col = 'service' if 'service' in df.columns else None
    condition_values = list(df['service'].value_counts().head(6).index) if condition_col else None
    ctgan_out_df = train_ctgan(df, ctgan_cols,
                               epochs=1200,
                               sample_n=3000,
                               save_path='ctgan_configs.json',
                               condition_col=condition_col,
                               condition_values=condition_values,
                               # Add these two lines:
                               )

    # Build sequences (overlapping windows), scale 0-1 for TimeGAN
    seqs, feats = build_sequences(df, seq_len=32, step=8)
    if seqs.shape < 100:
        seqs = np.random.normal(size=(400,32,len(feats))).astype('float32')

    seqs_scaled, scaler = minmax_scale_3d(seqs)

    # Train Supervised TimeGAN
    tg = SupervisedTimeGAN(seq_len=32, feature_dim=seqs_scaled.shape[2], hidden_dim=64, z_dim=64, lr=2e-4)
    tg.train(seqs_scaled, epochs=2000, batch_size=256)

    synth_scaled = tg.sample(min(2000, seqs_scaled.shape))
    synth_seq = minmax_inverse_3d(synth_scaled, scaler).astype('float32')

    # --- ML Efficacy: TSTR for CTGAN ---
    label_col = 'service' if df['service'].nunique() > 1 else 'state'
    acc, f1 = ctgan_tstr(df, ctgan_out_df, cols=ctgan_cols, label_col=label_col)
    print(f"[CTGAN TSTR] Accuracy: {acc:.3f}, F1: {f1:.3f}")

    # --- ML Efficacy: TSTR for TimeGAN ---
    acc_tg, f1_tg = timegan_tstr(seqs, synth_seq)
    print(f"[TimeGAN TSTR] Accuracy: {acc_tg:.3f}, F1: {f1_tg:.3f}")

    # --- Discriminative Score for TimeGAN ---
    disc_acc = timegan_discriminative(seqs_scaled, synth_scaled)
    print(f"[TimeGAN Discriminative Score] Accuracy: {disc_acc:.3f} (ideal ~0.5)")

    # --- Use TimeGAN outputs to drive honeypot behaviors ---
    rates, sizes, errs = seq_to_service_profile(synth_seq)
    honey = HoneydConfigGenerator()
    metadata = build_honeypot_metadata(ctgan_out_df, honey, base_ip='10.10.10', max_hosts=30,
                                       timegan_profiles=(rates, sizes, errs))

    # convert numpy types to Python
    def to_python(obj):
        if isinstance(obj, np.generic): return obj.item()
        if isinstance(obj, dict): return {k: to_python(v) for k,v in obj.items()}
        if isinstance(obj, list): return [to_python(v) for v in obj]
        return obj

    metadata_py = to_python(metadata)

    with open('honeypot_pool.yaml','w') as f:
        yaml.dump({'honeypots': metadata_py}, f, sort_keys=False)

    # Generate scripts for all services present
    all_services = set()
    for m in metadata_py:
        for s in m['services']:
            all_services.add(s['name'])
    honey.generate_honeypot_scripts(all_services, output_dir='honeypot_scripts')

    print('✅ Pipeline finished. Outputs: honeypot_pool.yaml, honeypot_scripts/, ctgan_configs.json')

if __name__ == '__main__':
    main()
