//! # tree
//!
//! Basic constructions for a sparse merkle tree.
//! Support construction from roots as well as path construction
//! and verification.

use crate::hash::{hash_two_stack, keccak256};
use alloc::vec::Vec;

/// The sparse merkle tree
/// Contains info on non-empty nodes
/// Assumed that the depth equals the vector length
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseTree {
    nodes: Vec<Vec<[u8; 32]>>,
}

/// A sibling struct for merkle proofs
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sibling {
    is_left: bool,
    node: [u8; 32],
}

/// A proof struct for the merkle tree
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    path: Vec<Sibling>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    EmptyTree,
}

impl SparseTree {
    /// Computes a canonical sparse merkle tree given an array of lists
    ///
    /// Stores only non-empty nodes in the tree, minimizing storage space.
    /// Errors on the empty leaves
    pub fn compute_tree(leaves: &[[u8; 32]]) -> Result<SparseTree, TreeError> {
        // an empty tree is not supported
        if leaves.is_empty() {
            return Err(TreeError::EmptyTree);
        }

        // get the minimal; depth required to store the leaves supplied
        let depth = leaves.len().next_power_of_two().ilog2() as usize;
        // compute all the empty nodes used per height
        let empty_nodes = empty_nodes(depth);
        let mut nodes: Vec<Vec<[u8; 32]>> = Vec::with_capacity(depth + 1);
        // leaves are the nodes at height 0
        nodes.push(leaves.to_vec());

        for depth_index in 0..depth {
            // the parents to compute are exactly twice as small as the children
            let next_level_capacity = (nodes[depth_index].len() + 1) / 2;
            let mut nodes_at_next_level: Vec<[u8; 32]> = Vec::with_capacity(next_level_capacity);
            for parent_index in 0..next_level_capacity {
                // either get the sibling, or the default node
                let right_child = match nodes[depth_index].get((parent_index * 2) + 1) {
                    Some(child) => child,
                    None => &empty_nodes[depth_index],
                };
                nodes_at_next_level.push(hash_two_stack(
                    &nodes[depth_index][parent_index * 2],
                    right_child,
                ));
            }
            nodes.push(nodes_at_next_level);
        }

        Ok(SparseTree { nodes })
    }

    /// Gets the root of a tree
    ///
    /// This is just the topmost entry of a well-formed tree
    pub fn root(&self) -> Option<&[u8; 32]> {
        self.nodes.last()?.first()
    }

    /// Computes a merkle proof for a given tree
    ///
    /// Returns `None` on a non-existing leaf or ill-formed tree
    pub fn prove_for(&self, leaf: &[u8; 32]) -> Option<Proof> {
        // get the first layer, i.e. the leaves
        let leaves = self.nodes.first()?;
        //try to search for the
        let mut index = leaves.iter().position(|h| h == leaf)?;

        let depth = self.nodes.len().checked_sub(1)?;
        let empty_nodes = empty_nodes(depth);
        let mut path: Vec<Sibling> = Vec::with_capacity(depth);

        for level in 0..depth {
            // the index of the sibling is just a bit-flip away
            let sibling_index = index ^ 1;
            // if there is no sibling, get a default one
            let sibling_node = self.nodes[level]
                .get(sibling_index)
                .copied()
                .unwrap_or(empty_nodes[level]);

            let is_left = index % 2 == 0;
            path.push(Sibling {
                node: sibling_node,
                is_left,
            });

            // the next index is exactly twice as small
            index /= 2;
        }

        Some(Proof { path })
    }
}

impl Proof {
    /// Verifies a merkle proof against a given root
    pub fn verify(&self, leaf: [u8; 32], root: [u8; 32]) -> bool {
        let asserted_root = self.compute_root(leaf);
        asserted_root == root
    }

    /// Compute the merkle tree root from a given path and leaf
    pub fn compute_root(&self, leaf: [u8; 32]) -> [u8; 32] {
        self.path.iter().fold(leaf, |acc, sibling| {
            if sibling.is_left {
                hash_two_stack(&sibling.node, &acc)
            } else {
                hash_two_stack(&acc, &sibling.node)
            }
        })
    }
}

/// Compute the default hashes for every level of a depth-provided sparse tree
/// where all the leaves are the keccak of the string "EMPTY"
pub fn empty_nodes(depth: usize) -> Vec<[u8; 32]> {
    let mut nodes = Vec::with_capacity(depth + 1);
    // the initial default node is a hash of the string "EMPTY"
    nodes.push(keccak256("EMPTY".as_bytes()));
    for i in 0..depth {
        // for the next level, the default hash is a hash of the
        // previously computed children
        nodes.push(hash_two_stack(&nodes[i], &nodes[i]));
    }

    nodes
}
