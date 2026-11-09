# Learn: the quantum ideas behind pqc-scan

Three short, runnable notebooks. They need only Python — no quantum SDK,
no NumPy — and run in Jupyter, VS Code or `python -m jupyter notebook`.

| Notebook | Question it answers |
| --- | --- |
| [`grover.ipynb`](grover.ipynb) | Why is AES-128 only *weakened* and AES-256 safe? |
| [`shor.ipynb`](shor.ipynb) | Why are RSA and elliptic curves *vulnerable* at any size? |
| [`bb84.ipynb`](bb84.ipynb) | How can quantum physics reveal an eavesdropper? |

A plain-language Turkish glossary is in [`../kuantum-rehberi.md`](../kuantum-rehberi.md).
The notebooks are executed by the test suite (`tests/test_learn_notebooks.py`),
so they stay correct.
