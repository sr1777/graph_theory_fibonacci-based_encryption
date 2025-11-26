

# Graph Theory based Encryption Algorithm 

Description

Developed a graph-theory-based encryption scheme.

Based on the paper by Wael Mahmoud Al Etaiwi as the foundational reference.

Initially used prime numbers for weight mapping, but encountered inconsistencies in the mathematical structure.

Refined the approach to use Fibonacci-based deterministic mappings, embedding byte differences in partition adjacency matrices diagonals for secure, reversible encoding.

Works in byte-space (0–255) with modulo arithmetic to avoid overflow.

## How It Works

1. Encode the message and add boundary bytes (`'a'` and `'z'`).
2. Build a **graph** with sequential edges representing byte differences.
3. Add **filler edges** to make the graph connected.
4. Split the graph into **partitions**; embed Fibonacci indices on diagonals of adjacency matrices.
5. For each partition:

   * Compute its **MST**.
   * Multiply partition matrix with MST to form intermediate matrix.
   * Multiply with an **invertible binary key matrix** to get the cipher matrix.
6. During decryption, the indices from diagonals are used to reconstruct byte differences, recovering the original message.



## Complexity

* **Time Complexity:**
  [
  O(p \cdot n^3)
  ]
  where (p) = number of partitions, (n) = number of bytes in the message.
* **Space Complexity:**
  [
  O(p \cdot n^2)
  ]
  storing partition matrices, MST matrices, key matrices, and cipher matrices.

## Requirements

* Python 3.8+
* `numpy`
* `networkx`

Install dependencies:

```bash
pip install numpy networkx
```

## License

MIT License – free to use and modify for educational and research purposes.

