"""
- Store the Fibonacci 'index' (index = delta + OFFSET) directly in the partition adjacency matrix M1
  on the diagonal for the node i corresponding to sequential edge (i -> i+1).
  partition_matrices are returned unchanged from encrypt() and passed to decrypt(),
  so these integer indices are preserved exactly (no floating noise).
- Decrypt reads indices from partition_matrices diagonals to reconstruct signed byte deltas.
- Keeps original pipeline: partitions -> M1 -> M2 (MST) -> M3 = M1*M2 -> K -> C
- Works in byte-space (0..255) with modulo arithmetic to avoid chr() overflow.
"""

from typing import List, Tuple, Dict
import numpy as np
import networkx as nx

# ---------- Fibonacci helpers ----------
def fib_fast_doubling_mod(n: int, m: int) -> int:
    def _fd(k: int):
        if k == 0:
            return (0, 1)
        a, b = _fd(k >> 1)
        c = (a * ((b << 1) - a)) % m
        d = (a * a + b * b) % m
        if k & 1:
            return (d, (c + d) % m)
        else:
            return (c, d)
    return int(_fd(n)[0])

# ---------- utilities ----------
def generate_invertible_binary_matrix(n: int, seed: int = None) -> np.ndarray:
    rng = np.random.RandomState(seed) if seed is not None else np.random.RandomState()
    for _ in range(2000):
        K = rng.randint(0, 2, (n, n)).astype(float)
        try:
            det = np.linalg.det(K)
            if abs(det) > 1e-10:
                inv = np.linalg.inv(K)
                if np.allclose(np.dot(K, inv), np.eye(n), atol=1e-6):
                    return K
        except np.linalg.LinAlgError:
            continue
    # fallback
    K = np.eye(n, dtype=float)
    for i in range(min(n-1, n)):
        K[i][(i+1) % n] = 1.0
    return K

# ---------- main class ----------
class FibonacciGraphEncryption:
    def __init__(self, modulus: int = 10000, offset: int = 512):
        self.modulus = int(modulus)
        self.offset = int(offset)
        if self.offset < 256:
            self.offset = 512
        self._fib_cache: Dict[int, int] = {}

    def _fib_mod(self, index: int) -> int:
        if index < 0:
            raise ValueError("Negative Fibonacci index: increase OFFSET.")
        if index in self._fib_cache:
            return self._fib_cache[index]
        val = fib_fast_doubling_mod(index, self.modulus)
        self._fib_cache[index] = int(val)
        return int(val)

    def _byte_delta(self, b_prev: int, b_next: int) -> int:
        return int(b_next) - int(b_prev)

    def encrypt(self, message: str, num_partitions: int = None, seed: int = None
               ) -> Tuple[List[np.ndarray], List[np.ndarray], List[np.ndarray], int]:
        payload = message.encode('utf-8') if isinstance(message, str) else bytes(message)
        bounded = b'a' + payload + b'z'
        n = len(bounded)

        if num_partitions is None:
            num_partitions = max(1, n // 2)
        print(f"Number of partitions used for this message: {num_partitions}")

        print(f"\nEncrypting message of length {len(payload)} using {num_partitions} partitions.")

        # Build full graph
        G = nx.Graph()
        G.add_nodes_from(range(n))

        sequential_info = {}  # i -> (delta, index, fib)
        max_index = 0

        for i in range(n - 1):
            delta = self._byte_delta(bounded[i], bounded[i + 1])
            index = delta + self.offset
            if index < 0:
                raise ValueError("OFFSET too small; increase offset.")
            fib_w = self._fib_mod(index)
            G.add_edge(i, i + 1, weight=int(fib_w))
            sequential_info[i] = {'delta': int(delta), 'index': int(index), 'fib': int(fib_w)}
            if index > max_index:
                max_index = index

        # filler edges
        filler_index = max_index + 500
        for i in range(n):
            for j in range(i + 2, n):
                if not G.has_edge(i, j):
                    w = self._fib_mod(filler_index)
                    G.add_edge(i, j, weight=int(w))
                    filler_index += 1

        # partitions
        edges = list(G.edges(data=True))
        partition_size = max(1, len(edges) // num_partitions)
        partitions: List[np.ndarray] = []
        for k in range(num_partitions):
            start = k * partition_size
            end = start + partition_size if k < num_partitions - 1 else len(edges)
            partition_edges = edges[start:end]
            M1 = np.zeros((n, n), dtype=float)
            for u, v, data in partition_edges:
                M1[u][v] = data['weight']
                M1[v][u] = data['weight']
            # embed the index into diagonal of M1 for sequential edges
            for i in range(n - 1):
                if M1[i][i+1] > 0 or M1[i+1][i] > 0:
                    M1[i][i] = float(sequential_info[i]['index'])
            partitions.append(M1)

        cipher_matrices: List[np.ndarray] = []
        key_matrices: List[np.ndarray] = []

        for p_idx, M1 in enumerate(partitions):
            # Build partition graph from M1
            partition_graph = nx.Graph()
            for i in range(n):
                for j in range(i + 1, n):
                    if M1[i][j] > 0:
                        partition_graph.add_edge(i, j, weight=M1[i][j])

            if len(partition_graph.edges()) > 0:
                mst = nx.minimum_spanning_tree(partition_graph)
            else:
                mst = nx.Graph()
                mst.add_nodes_from(range(n))

            # M2 from MST
            M2 = np.zeros((n, n), dtype=float)
            for u, v in mst.edges():
                wt = mst[u][v]['weight']
                M2[u][v] = wt
                M2[v][u] = wt

            # M3 = M1 * M2
            M3 = np.dot(M1, M2)

            # key K and C = K*M3
            partition_seed = (seed + p_idx) if seed is not None else None
            K = generate_invertible_binary_matrix(n, partition_seed)
            C = np.dot(K, M3)



            print(f"\n--- Partition {p_idx} ---")
            print(f"M1 (Partition matrix with indices on diagonal):\n{M1}\n")
            print(f"M2 (MST matrix):\n{M2}\n")
            print(f"Cipher matrix C:\n{C}\n")

            cipher_matrices.append(C)
            key_matrices.append(K)

        return cipher_matrices, key_matrices, partitions, n

    def decrypt(self, cipher_matrices: List[np.ndarray], key_matrices: List[np.ndarray],
                partition_matrices: List[np.ndarray], n: int, debug: bool = False) -> str:
        all_edges: Dict[Tuple[int, int], int] = {}
        recovered_indices: Dict[int, int] = {}

        for i in range(len(cipher_matrices)):
            C = cipher_matrices[i]
            K = key_matrices[i]
            M1 = partition_matrices[i]

            try:
                K_inv = np.linalg.inv(K)
            except np.linalg.LinAlgError:
                K_inv = np.linalg.pinv(K)
            M3 = np.dot(K_inv, C)
            M1_inv = np.linalg.pinv(M1)
            M2 = np.dot(M1_inv, M3)

            # Extract edges from M2 (MST edges)
            for u in range(n):
                for v in range(u + 1, n):
                    val = M2[u][v]
                    if abs(val) > 1e-6:
                        w_int = int(round(abs(val)))
                        key = (u, v)
                        if key not in all_edges:
                            all_edges[key] = w_int
                        else:
                            all_edges[key] = min(all_edges[key], w_int)

            # Read stored indices from M1 diagonal
            for u in range(n - 1):
                diag_val = M1[u][u]
                if abs(diag_val) > 0.5:
                    idx_int = int(round(diag_val))
                    if u not in recovered_indices:
                        recovered_indices[u] = idx_int

        # Reconstruct final graph & MST
        G_rec = nx.Graph()
        for (u, v), wt in all_edges.items():
            G_rec.add_edge(u, v, weight=wt)

        if len(G_rec.edges()) == 0:
            return ""

        final_mst = nx.minimum_spanning_tree(G_rec)

        if debug:
            print("\nRecovered indices:", recovered_indices)
            print("Final MST edges:")
            for u, v in final_mst.edges():
                print(f"{u} - {v} weight {final_mst[u][v]['weight']}")

        # Reconstruct bytes safely (mod 256)
        message_bytes: List[int] = []
        current_byte = ord('a')
        message_bytes.append(current_byte)

        for i in range(n - 1):
            if i in recovered_indices:
                index = recovered_indices[i]
                delta = int(index) - self.offset
                next_byte = (current_byte + delta) % 256
                message_bytes.append(next_byte)
                current_byte = next_byte

        b = bytes(message_bytes)
        if len(b) >= 1 and b[0] == ord('a'):
            b = b[1:]
        if len(b) >= 1 and b[-1] == ord('z'):
            b = b[:-1]
        try:
            decoded = b.decode('utf-8')
        except UnicodeDecodeError:
            decoded = b.decode('latin-1')
        return decoded


if __name__ == "__main__":
    print("=" * 70)
    
    print("=" * 70)

    enc = FibonacciGraphEncryption(modulus=10000, offset=512)

    user_msg = input("Enter plaintext message: ").strip()
    if not user_msg:
        user_msg = "hello"

    

    

    cipher_matrices, key_matrices, partition_matrices, n = enc.encrypt(user_msg, seed=42)
    recovered = enc.decrypt(cipher_matrices, key_matrices, partition_matrices, n, debug=True)

    print(f"\nOriginal message: {user_msg}")
    print(f"Recovered message: {recovered}")
    print("=" * 70)
