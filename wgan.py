import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import pandas as pd
from torch.autograd import Variable
import torch.autograd as autograd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, classification_report
from sklearn.neighbors import NearestNeighbors
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
import os
import random
import json
from scipy.spatial.distance import cdist

# Set random seeds for reproducibility
torch.manual_seed(42)
np.random.seed(42)
random.seed(42)

class Generator(nn.Module):
    def __init__(self, noise_dim=100, output_dim=64):
        super(Generator, self).__init__()
        
        self.model = nn.Sequential(
            # Input: noise_dim
            nn.Linear(noise_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(True),
            
            nn.Linear(256, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(True),
            
            nn.Linear(512, 1024),
            nn.BatchNorm1d(1024),
            nn.ReLU(True),
            
            nn.Linear(1024, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(True),
            
            nn.Linear(512, output_dim),
            nn.Tanh()  # Output in [-1, 1] range
        )
    
    def forward(self, z):
        return self.model(z)

class Critic(nn.Module):
    def __init__(self, input_dim=64):
        super(Critic, self).__init__()
        
        self.model = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3),
            
            nn.Linear(512, 256),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3),
            
            nn.Linear(256, 128),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3),
            
            nn.Linear(128, 64),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3),
            
            nn.Linear(64, 1)  # No sigmoid for WGAN
        )
    
    def forward(self, x):
        return self.model(x)

def gradient_penalty(critic, real_data, fake_data, device):
    """Calculate gradient penalty for WGAN-GP"""
    batch_size = real_data.shape[0]
    
    # Random weight term for interpolation between real and fake samples
    alpha = torch.rand(batch_size, 1).to(device)
    alpha = alpha.expand_as(real_data)
    
    interpolates = alpha * real_data + (1 - alpha) * fake_data
    interpolates = Variable(interpolates, requires_grad=True)
    
    critic_interpolates = critic(interpolates)
    
    gradients = autograd.grad(
        outputs=critic_interpolates,
        inputs=interpolates,
        grad_outputs=torch.ones(critic_interpolates.size()).to(device),
        create_graph=True,
        retain_graph=True,
        only_inputs=True
    )[0]
    
    gradient_penalty = ((gradients.norm(2, dim=1) - 1) ** 2).mean()
    return gradient_penalty

class GANMetrics:
    """Class to calculate GAN-specific precision and recall metrics"""
    
    def __init__(self, k=5):
        self.k = k  # Number of nearest neighbors for evaluation
    
    def compute_precision_recall(self, real_data, fake_data, k=None):
        """
        Compute precision and recall for GAN generated data.
        
        Precision: What fraction of generated samples are realistic?
        Recall: What fraction of real data modes are covered by generated samples?
        """
        if k is None:
            k = self.k
            
        real_data = np.array(real_data)
        fake_data = np.array(fake_data)
        
        # Precision: For each fake sample, check if its k-NN in real data is close enough
        precision_scores = []
        recall_scores = []
        
        # Build k-NN model on real data
        nbrs_real = NearestNeighbors(n_neighbors=k, algorithm='ball_tree').fit(real_data)
        
        # Calculate precision
        distances_fake_to_real, _ = nbrs_real.kneighbors(fake_data)
        precision_threshold = np.percentile(
            cdist(real_data, real_data, metric='euclidean').flatten(), 5
        )
        
        precision = np.mean(distances_fake_to_real[:, 0] <= precision_threshold)
        
        # Build k-NN model on fake data for recall calculation
        nbrs_fake = NearestNeighbors(n_neighbors=k, algorithm='ball_tree').fit(fake_data)
        
        # Calculate recall
        distances_real_to_fake, _ = nbrs_fake.kneighbors(real_data)
        recall = np.mean(distances_real_to_fake[:, 0] <= precision_threshold)
        
        return precision, recall
    
    def compute_fid_approximation(self, real_data, fake_data):
        """
        Compute an approximation of Frechet Inception Distance (FID)
        using sample statistics instead of Inception features
        """
        real_data = np.array(real_data)
        fake_data = np.array(fake_data)
        
        # Calculate means
        mu_real = np.mean(real_data, axis=0)
        mu_fake = np.mean(fake_data, axis=0)
        
        # Calculate covariances
        cov_real = np.cov(real_data, rowvar=False)
        cov_fake = np.cov(fake_data, rowvar=False)
        
        # Calculate FID approximation
        diff = mu_real - mu_fake
        fid_approx = np.sum(diff**2) + np.trace(cov_real + cov_fake - 2 * np.sqrt(cov_real @ cov_fake))
        
        return fid_approx
    
    def compute_coverage(self, real_data, fake_data, threshold_percentile=5):
        """
        Compute coverage: what percentage of real data modes are covered by fake data
        """
        real_data = np.array(real_data)
        fake_data = np.array(fake_data)
        
        # Calculate pairwise distances
        distances = cdist(real_data, fake_data, metric='euclidean')
        min_distances = np.min(distances, axis=1)
        
        # Determine threshold based on real data distribution
        real_distances = cdist(real_data, real_data, metric='euclidean')
        threshold = np.percentile(real_distances[real_distances > 0], threshold_percentile)
        
        # Coverage: fraction of real samples that have a close fake sample
        coverage = np.mean(min_distances <= threshold)
        
        return coverage

class HoneypotDataPreprocessor:
    def __init__(self):
        self.scalers = {}
        self.encoders = {}
        self.feature_names = []
        
    def preprocess_unsw_nb15(self, data_path):
        """Preprocess UNSW-NB15 dataset for honeypot generation"""
        # Load UNSW-NB15 dataset
        try:
            df = pd.read_csv(data_path)
        except:
            # Create sample data if dataset not available
            df = self._create_sample_data()
        
        # Select relevant features for honeypot configuration
        honeypot_features = [
            'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
            'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss',
            'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb',
            'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean',
            'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl',
            'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm'
        ]
        
        # Filter available columns
        available_features = [col for col in honeypot_features if col in df.columns]
        
        if not available_features:
            # Use all numeric columns if specific features not found
            available_features = df.select_dtypes(include=[np.number]).columns.tolist()[:32]
        
        df_filtered = df[available_features].copy()
        
        # Handle missing values
        df_filtered = df_filtered.fillna(0)
        
        # Encode categorical variables
        categorical_cols = df_filtered.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            le = LabelEncoder()
            df_filtered[col] = le.fit_transform(df_filtered[col].astype(str))
            self.encoders[col] = le
        
        # Scale numerical features
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(df_filtered)
        self.scalers['main'] = scaler
        self.feature_names = available_features
        
        return scaled_data
    
    def _create_sample_data(self):
        """Create sample network traffic data if UNSW-NB15 not available"""
        np.random.seed(42)
        n_samples = 10000
        
        data = {
            'proto': np.random.choice(['tcp', 'udp', 'icmp'], n_samples),
            'service': np.random.choice(['http', 'https', 'ssh', 'ftp', 'dns', 'smtp'], n_samples),
            'state': np.random.choice(['CON', 'FIN', 'REQ', 'RST'], n_samples),
            'spkts': np.random.exponential(10, n_samples),
            'dpkts': np.random.exponential(8, n_samples),
            'sbytes': np.random.exponential(1000, n_samples),
            'dbytes': np.random.exponential(800, n_samples),
            'rate': np.random.exponential(100, n_samples),
            'sttl': np.random.randint(32, 255, n_samples),
            'dttl': np.random.randint(32, 255, n_samples),
            'sload': np.random.exponential(50, n_samples),
            'dload': np.random.exponential(40, n_samples),
            'sloss': np.random.exponential(1, n_samples),
            'dloss': np.random.exponential(1, n_samples),
            'sinpkt': np.random.exponential(100, n_samples),
            'dinpkt': np.random.exponential(80, n_samples),
        }
        
        return pd.DataFrame(data)

class WGANGPHoneypotGenerator:
    def __init__(self, data_dim=64, noise_dim=100, learning_rate=1e-4, lambda_gp=10):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.data_dim = data_dim
        self.noise_dim = noise_dim
        self.lambda_gp = lambda_gp
        
        # Initialize networks
        self.generator = Generator(noise_dim, data_dim).to(self.device)
        self.critic = Critic(data_dim).to(self.device)
        
        # Optimizers
        self.g_optimizer = optim.Adam(self.generator.parameters(), lr=learning_rate, betas=(0.5, 0.9))
        self.c_optimizer = optim.Adam(self.critic.parameters(), lr=learning_rate, betas=(0.5, 0.9))
        
        self.preprocessor = HoneypotDataPreprocessor()
        self.metrics_calculator = GANMetrics()
        
        # Store training data for metrics calculation
        self.real_data_sample = None
        
    def train(self, data_path, epochs=1000, batch_size=64, critic_iterations=5):
        """Train the WGAN-GP model"""
        # Preprocess data
        data = self.preprocessor.preprocess_unsw_nb15(data_path)
        
        # Store a sample of real data for metrics calculation
        self.real_data_sample = data[:5000]  # Store 5000 samples for evaluation
        
        # Ensure data dimension matches model
        if data.shape[1] != self.data_dim:
            if data.shape[1] > self.data_dim:
                data = data[:, :self.data_dim]  # Truncate
            else:
                # Pad with zeros
                padding = np.zeros((data.shape[0], self.data_dim - data.shape[1]))
                data = np.concatenate([data, padding], axis=1)
        
        # Convert to tensor
        data_tensor = torch.FloatTensor(data).to(self.device)
        dataset = torch.utils.data.TensorDataset(data_tensor)
        dataloader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        print(f"Training WGAN-GP on {len(data)} samples...")
        
        # Store metrics for tracking
        metrics_history = {
            'epochs': [],
            'precision': [],
            'recall': [],
            'coverage': [],
            'fid_approx': []
        }
        
        for epoch in range(epochs):
            for batch_idx, (real_data,) in enumerate(dataloader):
                batch_size = real_data.shape[0]
                
                # Train Critic
                for _ in range(critic_iterations):
                    self.c_optimizer.zero_grad()
                    
                    # Real data
                    real_validity = self.critic(real_data)
                    
                    # Fake data
                    z = torch.randn(batch_size, self.noise_dim).to(self.device)
                    fake_data = self.generator(z)
                    fake_validity = self.critic(fake_data.detach())
                    
                    # Gradient penalty
                    gp = gradient_penalty(self.critic, real_data, fake_data, self.device)
                    
                    # Critic loss
                    c_loss = -torch.mean(real_validity) + torch.mean(fake_validity) + self.lambda_gp * gp
                    c_loss.backward()
                    self.c_optimizer.step()
                
                # Train Generator
                self.g_optimizer.zero_grad()
                
                z = torch.randn(batch_size, self.noise_dim).to(self.device)
                fake_data = self.generator(z)
                fake_validity = self.critic(fake_data)
                
                g_loss = -torch.mean(fake_validity)
                g_loss.backward()
                self.g_optimizer.step()
                
                if batch_idx % 100 == 0:
                    print(f"Epoch [{epoch}/{epochs}] Batch [{batch_idx}] "
                          f"C_loss: {c_loss.item():.4f} G_loss: {g_loss.item():.4f}")
            
            # Calculate metrics every 50 epochs
            if epoch % 50 == 0 or epoch == epochs - 1:
                metrics = self.evaluate_model()
                metrics_history['epochs'].append(epoch)
                metrics_history['precision'].append(metrics['precision'])
                metrics_history['recall'].append(metrics['recall'])
                metrics_history['coverage'].append(metrics['coverage'])
                metrics_history['fid_approx'].append(metrics['fid_approx'])
                
                print(f"\nEpoch [{epoch}] Evaluation Metrics:")
                print(f"Precision: {metrics['precision']:.4f}")
                print(f"Recall: {metrics['recall']:.4f}")
                print(f"Coverage: {metrics['coverage']:.4f}")
                print(f"FID Approximation: {metrics['fid_approx']:.4f}")
                print("-" * 50)
        
        # Plot metrics over training
        self.plot_metrics_history(metrics_history)
        
        return metrics_history
    
    def evaluate_model(self, num_samples=5000):
        """Evaluate the trained model using various metrics"""
        self.generator.eval()
        
        with torch.no_grad():
            # Generate fake samples
            z = torch.randn(num_samples, self.noise_dim).to(self.device)
            fake_data = self.generator(z).cpu().numpy()
            
            # Use stored real data sample
            real_data = self.real_data_sample[:num_samples]
            
            # Ensure dimensions match
            if real_data.shape[1] != fake_data.shape[1]:
                min_features = min(real_data.shape[1], fake_data.shape[1])
                real_data = real_data[:, :min_features]
                fake_data = fake_data[:, :min_features]
                print(f"Warning: Dimension mismatch fixed. Using {min_features} features.")
            
            # Calculate metrics
            precision, recall = self.metrics_calculator.compute_precision_recall(
                real_data, fake_data
            )
            
            coverage = self.metrics_calculator.compute_coverage(
                real_data, fake_data
            )
            
            fid_approx = self.metrics_calculator.compute_fid_approximation(
                real_data, fake_data
            )
            
            metrics = {
                'precision': precision,
                'recall': recall,
                'coverage': coverage,
                'fid_approx': fid_approx,
                'real_data_shape': real_data.shape,
                'fake_data_shape': fake_data.shape
            }
            
            return metrics
    
    def plot_metrics_history(self, metrics_history):
        """Plot the metrics over training epochs"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 8))
        
        # Precision plot
        axes[0, 0].plot(metrics_history['epochs'], metrics_history['precision'], 'b-o')
        axes[0, 0].set_title('Precision Over Training')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Precision')
        axes[0, 0].grid(True)
        
        # Recall plot
        axes[0, 1].plot(metrics_history['epochs'], metrics_history['recall'], 'r-o')
        axes[0, 1].set_title('Recall Over Training')
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Recall')
        axes[0, 1].grid(True)
        
        # Coverage plot
        axes[1, 0].plot(metrics_history['epochs'], metrics_history['coverage'], 'g-o')
        axes[1, 0].set_title('Coverage Over Training')
        axes[1, 0].set_xlabel('Epoch')
        axes[1, 0].set_ylabel('Coverage')
        axes[1, 0].grid(True)
        
        # FID Approximation plot
        axes[1, 1].plot(metrics_history['epochs'], metrics_history['fid_approx'], 'm-o')
        axes[1, 1].set_title('FID Approximation Over Training')
        axes[1, 1].set_xlabel('Epoch')
        axes[1, 1].set_ylabel('FID Approximation')
        axes[1, 1].grid(True)
        
        plt.tight_layout()
        plt.savefig('gan_metrics_history.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Metrics history plot saved as 'gan_metrics_history.png'")
    
    def generate_honeypot_configs(self, num_configs=10):
        """Generate honeypot configurations using trained generator"""
        self.generator.eval()
        
        with torch.no_grad():
            z = torch.randn(num_configs, self.noise_dim).to(self.device)
            fake_data = self.generator(z)
            
            # Convert back to original scale
            fake_data_np = fake_data.cpu().numpy()
            
            # Denormalize if scaler exists
            if 'main' in self.preprocessor.scalers:
                fake_data_np = self.preprocessor.scalers['main'].inverse_transform(fake_data_np)
            
            return fake_data_np
    
    def final_evaluation_report(self):
        """Generate a comprehensive evaluation report"""
        print("\n" + "="*60)
        print("FINAL GAN EVALUATION REPORT")
        print("="*60)
        
        metrics = self.evaluate_model(num_samples=5000)
        
        print(f"Model Performance Metrics:")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"    (What fraction of generated samples are realistic?)")
        print(f"  Recall: {metrics['recall']:.4f}")
        print(f"    (What fraction of real data modes are covered?)")
        print(f"  Coverage: {metrics['coverage']:.4f}")
        print(f"    (Percentage of real data modes covered by generated data)")
        print(f"  FID Approximation: {metrics['fid_approx']:.4f}")
        print(f"    (Lower is better - measures distributional similarity)")
        
        print(f"\nData Shapes:")
        print(f"  Real Data: {metrics['real_data_shape']}")
        print(f"  Generated Data: {metrics['fake_data_shape']}")
        
        # Interpretation
        print(f"\nInterpretation:")
        if metrics['precision'] > 0.7:
            print("  ✓ High precision - generated samples are realistic")
        elif metrics['precision'] > 0.5:
            print("  ~ Moderate precision - some generated samples are realistic")
        else:
            print("  ✗ Low precision - many generated samples are unrealistic")
            
        if metrics['recall'] > 0.7:
            print("  ✓ High recall - good coverage of real data distribution")
        elif metrics['recall'] > 0.5:
            print("  ~ Moderate recall - covers some of the real data distribution")
        else:
            print("  ✗ Low recall - poor coverage of real data distribution")
            
        if metrics['coverage'] > 0.8:
            print("  ✓ Excellent coverage of data modes")
        elif metrics['coverage'] > 0.6:
            print("  ~ Good coverage of data modes")
        else:
            print("  ✗ Poor coverage - may be missing important data modes")
        
        print("="*60)
        
        return metrics

class HoneyDConfigGenerator:
    def __init__(self):
        self.service_ports = {
            'http': 80,
            'https': 443,
            'ssh': 22,
            'ftp': 21,
            'smtp': 25,
            'dns': 53,
            'telnet': 23,
            'pop3': 110,
            'imap': 143,
            'snmp': 161
        }
        
        self.os_templates = [
            'Linux 2.6.x',
            'Windows XP',
            'Windows 7',
            'Windows 10',
            'FreeBSD',
            'OpenBSD',
            'Solaris'
        ]
    
    def generate_honeyd_config(self, generated_configs, base_ip="192.168.1"):
        """Convert generated configurations to HoneyD configuration"""
        config_lines = [
            "# HoneyD Configuration Generated by WGAN-GP",
            "# Dynamic Honeypot Configurations",
            "",
            "# Create templates",
        ]
        
        for i, config in enumerate(generated_configs):
            template_name = f"template{i+1}"
            ip_address = f"{base_ip}.{i+10}"
            
            # Extract features from generated config
            services = self._extract_services(config)
            os_type = random.choice(self.os_templates)
            
            # Create template
            config_lines.extend([
                f"create {template_name}",
                f"set {template_name} personality \"{os_type}\"",
                f"set {template_name} default tcp action block",
                f"set {template_name} default udp action block",
                f"set {template_name} default icmp action block",
            ])
            
            # Add services based on generated config
            for service, port in services.items():
                script_name = f"{service}_script.py"
                config_lines.extend([
                    f"add {template_name} tcp port {port} \"python scripts/{script_name}\"",
                ])
            
            # Bind to IP
            config_lines.extend([
                f"bind {ip_address} {template_name}",
                ""
            ])
        
        return "\n".join(config_lines)
    
    def _extract_services(self, config):
        """Extract services from generated configuration"""
        services = {}
        
        # Use probabilistic approach based on generated values
        config_normalized = (config - np.min(config)) / (np.max(config) - np.min(config) + 1e-8)
        
        service_list = list(self.service_ports.keys())
        num_services = min(len(service_list), max(1, int(np.mean(config_normalized) * 5)))
        
        # Select services based on config values
        for i in range(num_services):
            if i < len(config) and config_normalized[i] > 0.3:
                service = service_list[i % len(service_list)]
                services[service] = self.service_ports[service]
        
        # Ensure at least HTTP is included
        if not services:
            services['http'] = 80
            
        return services
    
    def generate_honeypot_scripts(self, services, output_dir="honeypot_scripts"):
        """Generate simple honeypot scripts for services"""
        os.makedirs(output_dir, exist_ok=True)
        
        scripts = {
            'http': '''#!/usr/bin/env python3
import socket
import sys

def http_honeypot():
    response = """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 100

<html><body><h1>Welcome to Apache Server</h1><p>Server is running normally.</p></body></html>"""
    
    print(response, end='')
    
    # Log the interaction
    with open('/var/log/honeyd/http.log', 'a') as f:
        f.write(f"HTTP connection from client\\n")

if __name__ == "__main__":
    http_honeypot()
''',
            'ssh': '''#!/usr/bin/env python3
import sys

def ssh_honeypot():
    banner = "SSH-2.0-OpenSSH_7.4\\r\\n"
    print(banner, end='')
    
    # Log the interaction
    with open('/var/log/honeyd/ssh.log', 'a') as f:
        f.write(f"SSH connection attempt\\n")

if __name__ == "__main__":
    ssh_honeypot()
''',
            'ftp': '''#!/usr/bin/env python3
def ftp_honeypot():
    banner = "220 FTP Server ready\\r\\n"
    print(banner, end='')
    
    # Log the interaction
    with open('/var/log/honeyd/ftp.log', 'a') as f:
        f.write(f"FTP connection attempt\\n")

if __name__ == "__main__":
    ftp_honeypot()
'''
        }
        
        for service in services:
            if service in scripts:
                script_path = os.path.join(output_dir, f"{service}_script.py")
                with open(script_path, 'w') as f:
                    f.write(scripts[service])
                os.chmod(script_path, 0o755)

def main():
    # Initialize the WGAN-GP honeypot generator
    generator = WGANGPHoneypotGenerator(data_dim=64, noise_dim=100)
    
    # Train the model (replace with actual UNSW-NB15 dataset path)
    print("Training WGAN-GP model...")
    metrics_history = generator.train("UNSW_NB15_training-set.csv", epochs=500, batch_size=64)
    
    # Generate final evaluation report
    final_metrics = generator.final_evaluation_report()
    
    # Generate honeypot configurations
    print("\nGenerating honeypot configurations...")
    configs = generator.generate_honeypot_configs(num_configs=5)
    
    # Convert to HoneyD configuration
    honeyd_generator = HoneyDConfigGenerator()
    honeyd_config = honeyd_generator.generate_honeyd_config(configs)
    
    # Save HoneyD configuration
    with open("honeyd.conf", "w") as f:
        f.write(honeyd_config)
    
    print("HoneyD configuration saved to honeyd.conf")
    
    # Generate honeypot scripts
    services = set()
    for config in configs:
        services.update(honeyd_generator._extract_services(config).keys())
    
    honeyd_generator.generate_honeypot_scripts(services)
    print("Honeypot scripts generated in honeypot_scripts/ directory")
    
    # Save final metrics to JSON
    with open("final_metrics.json", "w") as f:
        json.dump(final_metrics, f, indent=2)
    
    print("Final metrics saved to final_metrics.json")
    
    # Print sample configuration
    print("\n" + "="*50)
    print("SAMPLE HONEYD CONFIGURATION:")
    print("="*50)
    print(honeyd_config[:1000] + "..." if len(honeyd_config) > 1000 else honeyd_config)

if __name__ == "__main__":
    main()