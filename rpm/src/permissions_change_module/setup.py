from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

setup(
    name = 'permissions_change',
    ext_modules = cythonize(Extension("permissions_change", ["permissions_change.pyx", "permissions_changer.c"])),
    include_dirs = [
        '/usr/include/libxml2', 
        '/usr/lib64/python3.6/site-packages/lxml'
    ]
)