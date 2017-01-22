from setuptools import setup, find_packages

import versioneer

setup(
    name='unmessage',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description='Privacy enhanced instant messenger',
    url='https://github.com/AnemoneLabs/unmessage',
    author='Anemone Labs',
    author_email='anemone@anemone.me',
    license='GPLv3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Communications :: Chat',
    ],
    keywords='messenger privacy anonimity pyaxo axolotl double ratchet tor',
    packages=find_packages(),
    install_requires=[
        'pyaxo>=0.7.3',
        'PyNaCl>=1.0.1',
        'pyperclip>=1.5.27',
        'Twisted>=16.6.0',
        'txtorcon>=0.17.0',
    ],
    entry_points={
        'console_scripts': [
            'unmessage = unmessage.__main__:main',
            'unmessage-cli = unmessage.__main__:cli.main',
        ],
        'gui_scripts': [
            'unmessage-gui = unmessage.__main__:gui.main',
        ],
    },
)
