

# Graph Theory based Encryption Algorithm 

Description

Developed a graph-theory-based encryption scheme.

Based on the paper by Wael Mahmoud Al Etaiwi as the foundational reference.

Initially used prime numbers for weight mapping, but encountered inconsistencies in the mathematical structure.

Refined the approach to use Fibonacci-based deterministic mappings, embedding byte differences in partition adjacency matrices diagonals for secure, reversible encoding.

Works in byte-space (0–255) with modulo arithmetic to avoid overflow.

Validated the scheme on 15,715 bytes of input, yielding 7,858 Fibonacci-indexed partitions and perfect (100%) reversibility.
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



## Complexity Analysis
| Metric             | Complexity                     | Explanation                                                                 |
|--------------------|--------------------------------|-----------------------------------------------------------------------------|
| **Time**           | **O(p · n³)**                  | Dominated by complete-graph construction and repeated matrix multiplications |
| **Space**          | **O(p · n²)**                  | Stores partition matrices, MST matrices, key matrices, and cipher matrices  |

where  
- `p` = number of partitions (message length ≈ `p × n²` bytes)  
- `n` = partition dimension (side length of square matrix per partition)
- 
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



