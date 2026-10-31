from setuptools import setup, find_packages

setup(
    name="bpfstrike",
    version="1.0.0",
    description="BPFStrike — eBPF Offensive Security Framework",
    author="Dr. Sapna V M",
    url="https://github.com/p17433308-cmyk/BPFStrike",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "bpfstrike=bpfstrike.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
