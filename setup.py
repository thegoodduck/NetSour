from setuptools import setup, find_packages

setup(
    name='netsour',  # Replace with your desired package name
    version='0.1.0',
    description='A packet analyzer with enhanced features like Nmap scanning and geolocation',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='thegoodduck',  # Replace with your name or GitHub username
    author_email='your.email@example.com',  # Replace with your email
    url='https://github.com/thegoodduck/NetSour',  # Your repository URL
    license='GPL-3.0',  # Ensure it matches the LICENSE file
    packages=find_packages(),
    install_requires=[
        'scapy',
        'python-nmap',
        'requests'
    ],
    entry_points={
        'console_scripts': [
            'netsour = netsour.main:main'  # Entry point for the command-line tool
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
