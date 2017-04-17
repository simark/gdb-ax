from distutils.core import setup

setup(
    name='gdb-ax',
    version='1.0.0',
    packages=['disas'],
    url='https://github.com/simark/gdb-ax',
    license='GPLv3',
    author='simark',
    author_email='simon.marchi@polymtl.ca',
    description='GDB Agent Expression decoder',
    entry_points={
        'console_scripts': [
            'gdb-ax-disas=disas.disas:cli_main'
        ]
    },
)
