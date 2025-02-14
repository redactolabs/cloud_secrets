from setuptools import setup, find_packages

setup(
    name="cloud-secrets",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.26.0",
        "google-cloud-secret-manager>=2.16.0",
        "azure-keyvault-secrets>=4.7.0",
        "azure-identity>=1.12.0",
        "python-dotenv>=1.0.0",
    ],
    author="Redacto",
    author_email="support@redacto.io",
    description="A cloud-agnostic secrets management library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cloud-secrets",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
