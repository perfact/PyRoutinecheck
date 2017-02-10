# PyRoutinecheck

PyRoutinecheck - Toolkit for pythonized system checks

Requirements:
- Debian based linux distribution
- Python 2.7
- python-virtualenv

# Installation - Python Module - ROOT PERMISSION REQUIRED

Create a new python virtualenv, e.g. in /opt/venvs/pyroutinecheck

root@ubuntu:/opt/venv/pyroutinecheck# virtualenv .

Activate virtualenv, install requirements from repository into the virtualenv using pip

root@ubuntu:/opt/venv/pyroutinecheck# . ./bin/activate
(pyroutinecheck) root@ubuntu:/opt/venv/pyroutinecheck# pip install -r <PATH TO REPOSITORY/>/requirements.txt

Install pyroutinecheck module into virtualenv using setup.py

(pyroutinecheck) root@ubuntu:/opt/venv/pyroutinecheck# python <PATH TO REPOSITORY/>/setup.py

Test call for pyroutinecheck:

(pyroutinecheck) root@ubuntu:/opt/venv/pyroutinecheck# pyroutinecheck -d -c <PATH TO REPOSITORY/>/config/config.py


**Guide to make this a debian package for simpler instllation will follow soon!**
