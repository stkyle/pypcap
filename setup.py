#!/usr/bin/env python
#
# $Id$

from setuptools import setup, Extension
from distutils.command import config, clean
import cPickle, os, sys
import logging
import fnmatch
import platform
import sysconfig
from Cython.Build import cythonize

REQUIRES = ['dpkt', 'Cython', 'setuptools']
SOURCE_FILES = ['pcap.pyx', 'pcap_ex.c']
WIN_SDK_PATH = os.environ.get('WindowsSdkDir', None)
VCINSTALLDIR = os.environ.get('VCINSTALLDIR') or None


# Header Files
INC_WPCAP = r'C:\wpdpack\Include'
INC_PYTHON = sysconfig.get_paths().get('include', None)
INC_WINSDK = os.path.join(WIN_SDK_PATH,'Include') if WIN_SDK_PATH else None
INC_MSVC = os.path.join(VCINSTALLDIR, r'include') if VCINSTALLDIR else None

INCLUDE_PATHS = [INC_WPCAP, INC_PYTHON, INC_WINSDK, INC_MSVC]

# Libraries
LIB_WPACP = r'C:\wpdpack\Lib\x64'
LIB_PYTHON = r'C:\Anaconda3\envs\py2.7\libs'

#LIB_IPHLAPI = ctypes.util.find_library('iphlpapi')


# [ 'C:\wpdpack\Lib\x64', 'C:\Anaconda3\envs\py2.7\libs']



LIBRARIES = ['wpcap', 'iphlpapi']
EXTRA_COMPILE_ARGS = [ '-DWIN32', '-DWPCAP' ]

DEFINE_MACROS = []
#DEFINE_MACROS += [('HAVE_PCAP_INT_H', 0)]
DEFINE_MACROS += [('HAVE_PCAP_FILE', 1)]
DEFINE_MACROS += [('HAVE_PCAP_COMPILE_NOPCAP', 1)]
DEFINE_MACROS += [('HAVE_PCAP_SETNONBLOCK', 1)]
DEFINE_MACROS += [('HAVE_PCAP_SETDIRECTION', 1)]


sysconfig.get_config_vars()
PLATFORM = sys.platform
ARCH = 64 if sys.maxsize > 2**32 else 32
MACHINE = platform.machine()
PYCOMPILER = platform.python_compiler()
INTERPRETER = platform.python_implementation()


logging.basicConfig(level=logging.INFO)
pcap_config = {}
pcap_cache = 'config.pkl'


INCLUDE_DIRS = [r'C:\wpdpack\Include', 'C:\wpdpack\Include\pcap','C:\Anaconda3\envs\py2.7\include']
INCLUDE_DIRS += [r"C:\Users\steve.kyle\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\include"]
INCLUDE_DIRS += [r"C:\Users\steve.kyle\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\WinSDK\Include"]

LIB_DIRS = [r'C:\Anaconda3\envs\py2.7\libs']
LIB_DIRS += [r'C:\wpdpack\Lib\x64']
LIB_DIRS += [r'C:\Users\steve.kyle\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\WinSDK\Lib\x64']
LIB_DIRS += [r'C:\Users\steve.kyle\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\lib\amd64']
LIB_DIRS += [r'C:\pypcap', 'C:\pypcap\build']
LIB_DIRS += [r'C:\Anaconda3\envs\py2.7\Library\bin']




def getpcap_include_dirs():
    include_dirs = []
    for var in globals().keys():
        if var.startswith('INC_'):
            inc = globals()[var]
            logging.info('INCLUDE: %s' % inc)
            include_dirs += [inc]
    print include_dirs
    return include_dirs

def getpcap_lib_dirs():
    lib_dirs = []
    for var in globals().keys():
        if var.startswith('LIB_'):
            lib = globals()[var]
            logging.info('LIB: %s' % lib)
            lib_dirs += [lib]
    return lib_dirs


def findfilematch(name, path, recurse=False):
    """Search path or path list for file matching `name`"""
    if isinstance(path, str):
        path = [path]
    for p in path:
        
        for root, dirs, files in os.walk(p, topdown=True):
            if recurse is False: 
                dirs[:] = []
            
            for f in fnmatch.filter(files, name):
                return os.path.join(root, f)

    return None




class config_pcap(config.config):
    description = 'configure pcap paths'
    user_options = [ ('with-pcap=', None,
                      'path to pcap build or installation directory') ]
    
    def initialize_options(self):
        logging.info('Initializing Configuration Options...')
        config.config.initialize_options(self)
        self.dump_source = 0
        #self.noisy = 0
        self.with_pcap = None

    def _write_config_h(self, cfg):
        # XXX - write out config.h for pcap_ex.c
        logging.info('Writing configuration header files...')
        d = {}
        #if finfile('pcap-int.h', INCLUDE_DIRS) is not None:
        d['HAVE_PCAP_INT_H'] = 1
        
        #if finfile('pcap.h', INCLUDE_DIRS) is not None:
        d['HAVE_PCAP_FILE'] = 1
        
        #if os.path.exists(os.path.join(cfg['include_dirs'][0], 'pcap-int.h')):
        #    d['HAVE_PCAP_INT_H'] = 1
        print(findfilematch('pcap.h', INCLUDE_DIRS))
        buf = open(os.path.join(cfg['include_dirs'][0], 'pcap.h')).read()
        if buf.find('pcap_file(') != -1:
            d['HAVE_PCAP_FILE'] = 1
        if buf.find('pcap_compile_nopcap(') != -1:
            d['HAVE_PCAP_COMPILE_NOPCAP'] = 1
        if buf.find('pcap_setnonblock(') != -1:
            d['HAVE_PCAP_SETNONBLOCK'] = 1
        f = open('config.h', 'w')
        for k, v in d.iteritems():
            f.write('#define %s %s\n' % (k, v))
    
    def _pcap_config(self, dirs=[ None ]):
        logging.info('Writing configuration file...')
        cfg = {}
        cfg['include_dirs'] = ['C:\wpdpack\Include', 'C:\wpdpack\Include\pcap','C:\Anaconda3\envs\py2.7\include']
        cfg['include_dirs'] += ["C:\Users\XXXXX\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\include"]
        cfg['include_dirs'] += ["C:\Users\XXXXXXXXXXX\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\WinSDK\Include"]
        
        cfg['include_dirs'] = getpcap_include_dirs()

        cfg['library_dirs'] = [ r'C:\wpdpack\Lib\x64', 'C:\Anaconda3\envs\py2.7\libs']
        
        cfg['library_dirs'] = getpcap_lib_dirs()
        
        
        #cfg['libraries'] = [ 'wpcap', 'iphlpapi' ]
        cfg['extra_compile_args'] = [ '-DWIN32', '-DWPCAP' ]
        self._write_config_h(cfg)
        return cfg
								


    
    def run(self):
        #config.log.set_verbosity(0)
        cPickle.dump(self._pcap_config([ self.with_pcap ]),
                     open(pcap_cache, 'wb'))
        self.temp_files.append(pcap_cache)

class clean_pcap(clean.clean):
    def run(self):
        clean.clean.run(self)
        if self.all and os.path.exists(pcap_cache):
            print "removing '%s'" % pcap_cache
            os.unlink(pcap_cache)


pcap = Extension(name='pcap',
                 sources=SOURCE_FILES,
                 include_dirs=[d for d in INCLUDE_PATHS if d is not None],
                 define_macros=DEFINE_MACROS,
                 library_dirs=[LIB_WPACP, LIB_PYTHON],
                 libraries= LIBRARIES,
                 extra_compile_args=EXTRA_COMPILE_ARGS)

pcap_cmds = { 'config':config_pcap, 'clean':clean_pcap }

setup(name='pcap',
      version='2',
      author='Dug Song',
      author_email='dugsong@monkey.org',
      url='http://monkey.org/~dugsong/pypcap/',
      description='packet capture library',
      cmdclass=pcap_cmds,
      ext_modules = cythonize([pcap]))

