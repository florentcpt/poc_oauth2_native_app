# coding: utf-8
"""Setup file"""

__author__ = 'Florent Captier <florent@captier.org>'

from setuptools import setup, find_packages

setup(
    name='oauth2_client',
    use_scm_version=True,
    packages=find_packages(),
    url='',
    license='GNU',
    author='Florent Captier',
    author_email='florent@captier.org',
    description='',
    tests_require=['pytest'],
    setup_requires=['setuptools_scm'],
    platforms=['any'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
    ]
)
