from setuptools import setup, find_packages

setup(
    name="aibot-bug",
    version="4.0.0",
    author="ArkhAngelLifeJiggy",
    description="Ultimate AI-powered bug bounty beast for automated recon and vulnerability discovery.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Lifejiggy/AIbot-bug",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "google-generativeai",
        "requests",
        "tabulate",
        "colorama",
        "beautifulsoup4",
        "urllib3",
        "aiohttp",
        "python-dotenv",
    ],
    entry_points={
        "console_scripts": [
            "aibot-bug=aibot_bug.main:run_main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires='>=3.7',
)
