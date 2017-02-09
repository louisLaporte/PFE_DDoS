#!/usr/bin/env python3.4
import tarfile
import gzip
import re
import sys
import os
from functools import wraps

def path_isvalid(f):
    @wraps(f)
    def wrapper(*args, **kargs):
        key = 'path'

        if not key in kargs:
            raise NameError('keyword "path" does not exist')

        if not os.path.exists(kargs.get(key)):
            raise OSError("Path {} does not exist".format(kargs[key]))

        return f(*args, **kargs)
    return wrapper

@path_isvalid
def gunzip(path=None):
    with gzip.open(path, 'rt') as z:
        for l in z:
        #f = z.read()
            print(l)
        #return f

@path_isvalid
def tar(path=None, info=False, extension=None, extract=False):
    ''' Extract a tar file
    :param path: tar file path
    :param info: show tar info
    :param extension: get files match extension inside archive
    :param extract: hard uncompress on your system

    :Example:
    >>> import extract
    >>> archive = '../datasets/LLS_DDOS_1.0.tar.gz'
    >>> files = extract.tar(path=archive, extension='.dump')

    '''
    if not tarfile.is_tarfile(path):
        raise tarfile.TarError("file is not a tar file")
    found_files = []

    print("Start extraction for {}".format(path))
    print("search extension {} ...".format(extension))
    with tarfile.open(name=path) as tarchive:
        archives = [a for a in tarchive if a.isfile() and not '*' in a.name]

        if info:
            print(len(archives))
            print(tarchive.getnames())

        for a in archives:
            ext = os.path.splitext(a.name)[1]

            if ext == extension:
                found_files.append(a)
                if 0: # read content
                    with tarchive.extractfile(a) as f:
                        return f.read()
        print("Extraction finished")
        return found_files

# example
