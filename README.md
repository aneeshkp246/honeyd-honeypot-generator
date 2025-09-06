Honeypot Pipeline (CTGAN + TimeGAN) - Example Repository
=======================================================

This archive contains:
- ctgan_timegan_pipeline.py : main pipeline that trains CTGAN and TimeGAN, generates honeyd.conf and honeypot scripts.
- honeyd_config_generator.py : helper module that converts generated vectors into honeyd.conf and simple service scripts.
- provision_honeypot_vm.sh : provisioning script for an Ubuntu VM to install honeyd and deploy generated configs/scripts.
- Dockerfile : optional Dockerfile for running honeyd in a container (requires compiling/providing honeyd binary).
- Vagrantfile and vagrant/provision_vagrant.sh : pre-made Vagrant setup to spin up an Ubuntu VM and provision honeyd automatically.
- requirements.txt : Python dependencies for the pipeline.
- wgan.py : (user-provided) original WGAN-GP honeypot generator (included here for completeness).
- LICENSE (MIT)
- deploy_manifest_example.json : example manifest produced by running the pipeline.

How to use (quick):
1. unzip the repo
2. (optional) create a Python venv and install requirements:
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
3. Run the pipeline (small epochs by default):
   python3 ctgan_timegan_pipeline.py
4. Copy honeyd.conf and honeypot_scripts/ to a VM and run the provisioning script or use Vagrant:
   vagrant up

Security & Safety:
- Deploy honeypots only in controlled/test networks or with explicit permission on public IPs.
- Logs may contain attacker data; secure them appropriately.
