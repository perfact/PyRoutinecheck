# -*- coding: utf-8 -*-

from distutils.core import setup
setup(
    name='pyroutinecheck',
    version='0.2',
    description='Pythonized routinecheck',
    long_description='''New routinecheck written in python with ability to implement custom checks easily.''',
    author='Lars Bergmann',
    author_email='devel@perfact.de',
    packages=[
        'pyroutinecheck',
    ],
    license='GPLv2',
    scripts=['bin/pyroutinecheck'],
    platforms=['Linux',],
)
