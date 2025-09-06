# ctgan_timegan_pipeline.py
import os, json, numpy as np, pandas as pd, yaml
from sdv.single_table import CTGANSynthesizer
from sdv.metadata import SingleTableMetadata
from honeyd_config_generator import HoneydConfigGenerator

import tensorflow as tf
from tensorflow.keras import layers, Model
from tensorflow.keras.optimizers import Adam

# --------------------------
# Load Dataset
# --------------------------
def load_unsw(path='UNSW_NB15_training-set.csv'):
    if os.path.exists(path):
        df = pd.read_csv(path)
    else:
        n = 3000
        df = pd.DataFrame({
            'proto': np.random.choice(['tcp','udp','icmp'],n),
            'service': np.random.choice(['http','ssh','ftp','dns','smtp'], n),
            'state': np.random.choice(['CON','FIN','REQ','RST'], n),
            'spkts': np.random.exponential(10, n).astype(int),
            'dpkts': np.random.exponential(8, n).astype(int),
            'sbytes': np.random.exponential(1000, n).astype(int),
            'dbytes': np.random.exponential(800, n).astype(int),
            'timestamp': np.linspace(0, 1000, n).astype(int),
        })
    return df

# --------------------------
# Train CTGAN
# --------------------------
def train_ctgan(df, ctgan_cols, epochs=200, sample_n=100, save_path='ctgan_configs.json'):
    df_ct = df.copy()
    available = [c for c in ctgan_cols if c in df_ct.columns]
    df_ct = df_ct[available].fillna('NA')

    metadata = SingleTableMetadata()
    metadata.detect_from_dataframe(data=df_ct)

    # avoid 'state' as primary key
    if metadata.primary_key == 'state':
        metadata.primary_key = None
    if 'state' in metadata.columns:
        metadata.columns['state'].pop('key', None)

    model_path = 'ctgan_model.pkl'
    if os.path.exists(model_path):
        synthesizer = CTGANSynthesizer.load(model_path)
    else:
        synthesizer = CTGANSynthesizer(metadata, epochs=epochs, verbose=True)
        synthesizer.fit(df_ct)
        synthesizer.save(model_path)

    samples_df = synthesizer.sample(num_rows=sample_n)
    samples = samples_df.to_dict(orient='records')

    with open(save_path,'w') as f:
        json.dump(samples, f, indent=2)

    return samples

# --------------------------
# Minimal TimeGAN
# --------------------------
class TimeGAN:
    def __init__(self, seq_len, feature_dim, hidden_dim=24, z_dim=32, lr=1e-4):
        self.seq_len = seq_len
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.z_dim = z_dim
        self._build()
        self.opt = Adam(lr)

    def _build(self):
        # encoder
        inp = layers.Input(shape=(self.seq_len, self.feature_dim))
        x = layers.TimeDistributed(layers.Dense(self.hidden_dim, activation='relu'))(inp)
        x = layers.LSTM(self.hidden_dim, return_sequences=True)(x)
        self.encoder = Model(inp, x)

        # decoder
        inp2 = layers.Input(shape=(self.seq_len, self.hidden_dim))
        x2 = layers.LSTM(self.hidden_dim, return_sequences=True)(inp2)
        x2 = layers.TimeDistributed(layers.Dense(self.feature_dim))(x2)
        self.decoder = Model(inp2, x2)

        # generator
        zin = layers.Input(shape=(self.seq_len, self.z_dim))
        xg = layers.TimeDistributed(layers.Dense(self.hidden_dim, activation='relu'))(zin)
        xg = layers.LSTM(self.hidden_dim, return_sequences=True)(xg)
        xg = layers.TimeDistributed(layers.Dense(self.feature_dim))(xg)
        self.generator = Model(zin, xg)

        # discriminator
        din = layers.Input(shape=(self.seq_len, self.feature_dim))
        xd = layers.LSTM(self.hidden_dim)(din)
        xd = layers.Dense(1, activation='sigmoid')(xd)
        self.discriminator = Model(din, xd)

    def train(self, real, epochs=100, batch_size=64):
        n = real.shape[0]
        for epoch in range(epochs):
            idx = np.random.permutation(n)
            for start in range(0, n, batch_size):
                bidx = idx[start:start+batch_size]
                xb = real[bidx]
                # simple reconstruction
                with tf.GradientTape() as tape:
                    h = self.encoder(xb)
                    rec = self.decoder(h)
                    loss = tf.reduce_mean(tf.square(xb - rec))
                grads = tape.gradient(loss, self.encoder.trainable_variables + self.decoder.trainable_variables)
                self.opt.apply_gradients(zip(grads, self.encoder.trainable_variables + self.decoder.trainable_variables))
            if epoch % 20 == 0:
                print(f"[TimeGAN] epoch {epoch} recon_loss {loss.numpy():.4f}")

    def sample(self, n):
        z = np.random.normal(size=(n, self.seq_len, self.z_dim)).astype('float32')
        return self.generator.predict(z)

# --------------------------
# Sequence Builder
# --------------------------
def build_sequences(df, seq_len=16, feature_cols=None):
    if feature_cols is None:
        numeric = df.select_dtypes(include=[np.number]).columns.tolist()
        feature_cols = numeric[:4] if numeric else ['spkts','dpkts','sbytes','dbytes']
    arr = df[feature_cols].fillna(0).values
    seqs = []
    for i in range(0, max(0, len(arr)-seq_len+1), seq_len):
        seqs.append(arr[i:i+seq_len])
    return np.array(seqs).astype('float32'), feature_cols

# --------------------------
# Main
# --------------------------
def main():
    df = load_unsw()

    ctgan_cols = ['proto','service','state','spkts','dpkts','sbytes','dbytes']
    ctgan_out = train_ctgan(df, ctgan_cols, epochs=200, sample_n=100)

    seqs, feats = build_sequences(df, seq_len=16)
    if seqs.shape[0] < 10:
        seqs = np.random.normal(size=(200,16,len(feats))).astype('float32')

    tg = TimeGAN(seq_len=16, feature_dim=len(feats), hidden_dim=32, z_dim=32)
    tg.train(seqs, epochs=100, batch_size=64)

    honey = HoneydConfigGenerator()
    metadata = []
    base_ip = '10.10.10'

    for i, cfg in enumerate(ctgan_out):
        vec = []
        for k,v in cfg.items():
            if isinstance(v,(int,float)): vec.append(float(v))
            elif isinstance(v,str): vec.append(float(sum(map(ord,v))%100)/100.0)
            else: vec.append(0.0)
        while len(vec) < 32: vec.append(0.0)
        vec = np.array(vec[:32])

        ip = f'{base_ip}.{10+i}'
        os_type = np.random.choice(honey.os_templates)
        services = honey._extract_services(vec)
        service_meta = []
        for svc, port in services.items():
            script_path = f'honeypot_scripts/{svc}_script.py'
            banner = honey.get_banner(svc)
            service_meta.append({
                'name': svc,
                'port': port,
                'banner': banner,
                'script': script_path
            })
        metadata.append({
            'ip': ip,
            'os': os_type,
            'template': f'template{i}',
            'services': service_meta
        })

    # convert numpy types to Python
    def to_python(obj):
        if isinstance(obj, np.generic):
            return obj.item()
        if isinstance(obj, dict):
            return {k: to_python(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [to_python(v) for v in obj]
        return obj

    metadata_py = to_python(metadata)

    # save pool YAML
    with open('honeypot_pool.yaml','w') as f:
        yaml.dump({'honeypots': metadata_py}, f, sort_keys=False)

    # generate service scripts
    all_services = set()
    for m in metadata:
        for s in m['services']:
            all_services.add(s['name'])
    honey.generate_honeypot_scripts(all_services, output_dir='honeypot_scripts')

    print('✅ Pipeline finished. Outputs: honeypot_pool.yaml, honeypot_scripts/, ctgan_configs.json')

if __name__ == '__main__':
    main()
