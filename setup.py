from setuptools import setup, find_packages

import versioneer

# Hmmmph.
# So we get all the meta-information in one place (yay!) but we call
# exec to get it (boo!). Note that we can't import fom _metadata here
# because that won't work when setup is being run by pip (outside of
# Git checkout etc)
with open('unmessage/_metadata.py') as f:
    exec(
        compile(f.read(), '_metadata.py', 'exec'),
        globals(),
        locals(),
    )

setup(
    name='unmessage',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description='Privacy enhanced instant messenger',
    url=__url__,
    author=__author__,
    author_email=__contact__,
    license=__license__,
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
        'opuslib>=1.1.0',
        'PyAudio>=0.2.10',
        'pyaxo>=0.7.3',
        'PyNaCl>=1.0.1',
        'pyperclip>=1.5.27',
        'Twisted[tls]>=16.6.0',
        'txtorcon>=0.19.0',
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
