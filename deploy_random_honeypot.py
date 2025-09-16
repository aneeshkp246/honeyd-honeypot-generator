# deploy_random_honeypot.py
import os
from honeyd_config_generator import HoneydConfigGenerator

def main():
    # Define paths relative to script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    yaml_path = os.path.join(script_dir, 'honeypot_pool.yaml')
    vagrant_conf_path = os.path.join(script_dir, 'vagrant', 'honeyd.conf')
    
    # Create config generator
    honey = HoneydConfigGenerator()
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(vagrant_conf_path), exist_ok=True)
    
    # Generate config
    try:
        honey.generate_random_honeyd_config(yaml_path, vagrant_conf_path)
        print(f'Config successfully written to {vagrant_conf_path}')
        print('Ready to spin up VM with Vagrant.')
    except Exception as e:
        print(f'Error generating config: {str(e)}')

if __name__ == '__main__':
    main()
