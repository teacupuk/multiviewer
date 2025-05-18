from setuptools import setup

APP = ['main.py']
DATA_FILES = ['address_book.json', 'settings.json', 'app_icon.png']
OPTIONS = {
    'packages': ['psutil'],
    'includes': ['PyQt5', 'json', 'os', 'socket', 'subprocess', 'struct'],
    'resources': ['address_book.json', 'settings.json'],
    'iconfile': 'app_icon.png',
    'plist': {
        'CFBundleName': 'Multiview',
        'CFBundleIdentifier': 'net.viusao.multiview',
        'CFBundleShortVersionString': '1.0.2',
        'CFBundleVersion': '1.0.2',
    }
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)