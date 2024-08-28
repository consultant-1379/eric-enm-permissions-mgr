import os
os.chdir('..')
def listdirs(rootdir):
    dirs = [rootdir]
    for file in os.listdir(rootdir):
        d = os.path.join(rootdir, file)
        if os.path.isdir(d):
            dirs.append(d)
    print(dirs)

listdirs("tests/foo")