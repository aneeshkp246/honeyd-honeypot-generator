# deploy_random_honeypot.py
import os
from honeyd_config_generator import HoneydConfigGenerator

def main():
    yaml_path = 'honeypot_pool.yaml'
    vagrant_conf_path = os.path.join('vagrant', 'honeyd.conf')
    honey = HoneydConfigGenerator()
    # Generate a random config and write to vagrant/honeyd.conf
    honey.generate_random_honeyd_config(yaml_path, vagrant_conf_path)
    print(f'Config written to {vagrant_conf_path}. Ready to spin up VM with Vagrant.')

if __name__ == '__main__':
    main()
