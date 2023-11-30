use sha2::{Digest, Sha256};

pub trait SumCommitment {
    fn amount(&self) -> u64;
    fn digest(&self) -> [u8; 32];
}

pub trait ExclusiveAllotmentProof<C: SumCommitment> {
    fn position(&self) -> usize;
    fn sibling(&self, height: u8) -> Option<C>;
    fn verify(&self, root_commitment: &C) -> bool;
}

pub trait MerkleTree<C: SumCommitment, P: ExclusiveAllotmentProof<C>> {
    fn new(values: Vec<u64>) -> Self;
    fn commit(&self) -> C;
    fn prove(&self, position: usize) -> P;
}

fn hash_bytes(slice: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(slice);
    hasher.finalize().into()
}

// ------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Commitment {
    pub sum: u64,
    pub hash: [u8; 32],
}

impl SumCommitment for Commitment {
    fn amount(&self) -> u64 {
        self.sum
    }
    fn digest(&self) -> [u8; 32] {
        self.hash
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Node {
    Branch {
        height: usize,
        sum: u64,
        left: Box<Node>,
        right: Box<Node>,
        commitment: [u8; 32],
    },
    Leaf {
        value: u64,
        commitment: [u8; 32],
    },
}

impl Node {
    pub fn height(&self) -> usize {
        match self {
            Node::Branch { height, .. } => *height,
            Node::Leaf { .. } => 0,
        }
    }

    pub fn new_branch(left: Node, right: Node) -> Self {
        // We only deal with balanced trees
        assert!(left.height() == right.height());
        // Own height is one level above
        let height = left.height() + 1;
        let sum = left.amount() + right.amount();
        let serialized = [
            height.to_be_bytes().as_slice(),
            sum.to_be_bytes().as_slice(),
            left.digest().as_slice(),
            right.digest().as_slice(),
        ]
        .concat();

        let left = Box::new(left);
        let right = Box::new(right);
        let commitment = hash_bytes(&serialized);
        Self::Branch {
            height,
            sum,
            left,
            right,
            commitment,
        }
    }

    pub fn new_leaf(value: u64) -> Self {
        let serialized = value.to_be_bytes();
        let commitment = hash_bytes(&serialized);

        Self::Leaf { value, commitment }
    }
}

impl From<&Node> for Commitment {
    fn from(node: &Node) -> Commitment {
        Self {
            sum: node.amount(),
            hash: node.digest(),
        }
    }
}

impl SumCommitment for Node {
    fn amount(&self) -> u64 {
        match self {
            Node::Branch { sum, .. } => *sum,
            Node::Leaf { value, .. } => *value,
        }
    }

    fn digest(&self) -> [u8; 32] {
        match self {
            Node::Branch { commitment, .. } => *commitment,
            Node::Leaf { commitment, .. } => *commitment,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Proof {
    pub node: Commitment,
    pub siblings: Vec<Commitment>,
    pub index: usize,
}

impl ExclusiveAllotmentProof<Commitment> for Proof {
    fn position(&self) -> usize {
        self.index
    }
    fn sibling(&self, height: u8) -> Option<Commitment> {
        self.siblings.get(height as usize).copied()
    }

    fn verify(&self, root_commitment: &Commitment) -> bool {
        let mut commitment = self.node;
        let mut height = 0usize;
        let mut key = self.index;
        for sibling_commitment in &self.siblings {
            let (left, right) = if (key & 1) == 0 {
                (&commitment, sibling_commitment)
            } else {
                (sibling_commitment, &commitment)
            };
            let sum = commitment.amount() + sibling_commitment.amount();
            height += 1;
            key >>= 1;

            let serialized = [
                height.to_be_bytes().as_slice(),
                sum.to_be_bytes().as_slice(),
                left.digest().as_slice(),
                right.digest().as_slice(),
            ]
            .concat();

            let hash = hash_bytes(&serialized);

            commitment = Commitment { sum, hash }
        }

        &commitment == root_commitment
    }
}

impl MerkleTree<Commitment, Proof> for Node {
    fn new(values: Vec<u64>) -> Self {
        let mut roots: Vec<(usize, Node)> = Vec::new();

        for val in values {
            let mut node = Node::new_leaf(val);
            let mut height = 0usize;
            // bubble up new leaf
            while roots
                .last()
                .is_some_and(|(range_height, _)| &height == range_height)
            {
                let (_, sibling) = roots.pop().unwrap();
                node = Node::new_branch(sibling, node);
                height += 1;
            }
            roots.push((height, node));
        }

        // We only deal with 2^n values
        assert!(roots.len() == 1);
        // Return tree
        roots.pop().unwrap().1
    }

    fn commit(&self) -> Commitment {
        self.into()
    }

    fn prove(&self, position: usize) -> Proof {
        let mut siblings = Vec::new();

        let mut current = self;
        let node = loop {
            match current {
                Node::Branch { left, right, .. } => {
                    let mask = 1usize << (current.height() - 1);
                    if (position & mask) == 0 {
                        // descend left, taking right sibling
                        siblings.push(Commitment::from(right.as_ref()));
                        current = left.as_ref()
                    } else {
                        // descend right, taking left sibling
                        siblings.push(Commitment::from(left.as_ref()));
                        current = right.as_ref()
                    }
                }
                Node::Leaf { .. } => break Commitment::from(current),
            }
        };

        siblings.reverse();

        Proof {
            node,
            siblings,
            index: position,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_happy() {
        let values = vec![1, 2, 3, 4, 5, 6u64, 7, 8];
        let tree_root = Node::new(values);
        let root_commitment = tree_root.commit();
        for i in 0..8 {
            let proof = tree_root.prove(i);
            assert!(proof.verify(&root_commitment), "Failed Iteration {}", i);
        }
    }
}

