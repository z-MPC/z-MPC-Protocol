//! Network communication module for z-MPC
//! 
//! Provides distributed communication for:
//! - Share distribution
//! - Commitment exchange
//! - Proof verification
//! - Secret reconstruction

use crate::{Error, Result, CurveType, ShareId};
use crate::laurent::{Share, LaurentSeries};
use crate::pedersen::{PedersenCommitment, CommittedShare};
use crate::zkp::ZeroKnowledgeProof;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use axum::{
    routing::{post, get},
    http::StatusCode,
    Json, Router,
    extract::State,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Network message types for z-MPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Share distribution message
    ShareDistribution {
        sender_id: ShareId,
        shares: Vec<Share>,
        commitments: Vec<CommittedShare>,
        proofs: Vec<ZeroKnowledgeProof>,
        curve_type: CurveType,
    },
    
    /// Commitment verification request
    CommitmentVerification {
        sender_id: ShareId,
        commitment: Vec<u8>,
        value: Vec<u8>,
        randomness: Vec<u8>,
        curve_type: CurveType,
    },
    
    /// Commitment verification response
    CommitmentVerificationResponse {
        sender_id: ShareId,
        commitment: Vec<u8>,
        is_valid: bool,
    },
    
    /// Proof verification request
    ProofVerification {
        sender_id: ShareId,
        proof: ZeroKnowledgeProof,
    },
    
    /// Proof verification response
    ProofVerificationResponse {
        sender_id: ShareId,
        proof_commitment: Vec<u8>,
        is_valid: bool,
    },
    
    /// Secret reconstruction request
    SecretReconstruction {
        sender_id: ShareId,
        shares: Vec<Share>,
        curve_type: CurveType,
    },
    
    /// Secret reconstruction response
    SecretReconstructionResponse {
        sender_id: ShareId,
        secret: Vec<u8>,
        participants_used: Vec<ShareId>,
        is_valid: bool,
    },
    
    /// Heartbeat message
    Heartbeat {
        sender_id: ShareId,
        timestamp: u64,
    },
    
    /// Error message
    Error {
        sender_id: ShareId,
        error: String,
    },
}

/// Network participant information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub id: ShareId,
    pub address: SocketAddr,
    pub curve_type: CurveType,
    pub is_online: bool,
    pub last_heartbeat: u64,
}

/// Network node for z-MPC
#[derive(Clone)]
pub struct NetworkNode {
    pub id: ShareId,
    pub address: SocketAddr,
    pub curve_type: CurveType,
    pub participants: Arc<RwLock<HashMap<ShareId, Participant>>>,
    pub message_sender: mpsc::Sender<NetworkMessage>,
    pub message_receiver: mpsc::Receiver<NetworkMessage>,
}

impl NetworkNode {
    /// Create new network node
    pub fn new(id: ShareId, address: SocketAddr, curve_type: CurveType) -> Self {
        let (message_sender, message_receiver) = mpsc::channel(1000);
        
        Self {
            id,
            address,
            curve_type,
            participants: Arc::new(RwLock::new(HashMap::new())),
            message_sender,
            message_receiver,
        }
    }
    
    /// Add participant to network
    pub async fn add_participant(&self, participant: Participant) -> Result<()> {
        let mut participants = self.participants.write().await;
        participants.insert(participant.id, participant);
        Ok(())
    }
    
    /// Remove participant from network
    pub async fn remove_participant(&self, participant_id: ShareId) -> Result<()> {
        let mut participants = self.participants.write().await;
        participants.remove(&participant_id);
        Ok(())
    }
    
    /// Send message to all participants
    pub async fn broadcast(&self, message: NetworkMessage) -> Result<()> {
        let participants = self.participants.read().await;
        for participant in participants.values() {
            if participant.is_online {
                // In a real implementation, this would send over the network
                tracing::info!("Broadcasting to participant {}: {:?}", participant.id, message);
            }
        }
        Ok(())
    }
    
    /// Send message to specific participant
    pub async fn send_to(&self, participant_id: ShareId, message: NetworkMessage) -> Result<()> {
        let participants = self.participants.read().await;
        if let Some(participant) = participants.get(&participant_id) {
            if participant.is_online {
                // In a real implementation, this would send over the network
                tracing::info!("Sending to participant {}: {:?}", participant_id, message);
            }
        }
        Ok(())
    }
    
    /// Process incoming message
    pub async fn process_message(&mut self, message: NetworkMessage) -> Result<()> {
        match message {
            NetworkMessage::ShareDistribution { sender_id, shares, commitments, proofs, curve_type } => {
                self.handle_share_distribution(sender_id, shares, commitments, proofs, curve_type).await?;
            }
            NetworkMessage::CommitmentVerification { sender_id, commitment, value, randomness, curve_type } => {
                self.handle_commitment_verification(sender_id, commitment, value, randomness, curve_type).await?;
            }
            NetworkMessage::ProofVerification { sender_id, proof } => {
                self.handle_proof_verification(sender_id, proof).await?;
            }
            NetworkMessage::SecretReconstruction { sender_id, shares, curve_type } => {
                self.handle_secret_reconstruction(sender_id, shares, curve_type).await?;
            }
            NetworkMessage::Heartbeat { sender_id, timestamp } => {
                self.handle_heartbeat(sender_id, timestamp).await?;
            }
            _ => {
                tracing::warn!("Unhandled message type: {:?}", message);
            }
        }
        Ok(())
    }
    
    /// Handle share distribution
    async fn handle_share_distribution(
        &self,
        sender_id: ShareId,
        shares: Vec<Share>,
        commitments: Vec<CommittedShare>,
        proofs: Vec<ZeroKnowledgeProof>,
        curve_type: CurveType,
    ) -> Result<()> {
        tracing::info!("Received share distribution from participant {}", sender_id);
        
        // Verify commitments
        let pedersen = PedersenCommitment::new(curve_type)?;
        for committed_share in &commitments {
            if !committed_share.verify(curve_type)? {
                return Err(Error::CommitmentError("Invalid commitment".to_string()));
            }
        }
        
        // Verify proofs
        for proof in &proofs {
            if !proof.verify(&pedersen)? {
                return Err(Error::ZKProofError("Invalid proof".to_string()));
            }
        }
        
        tracing::info!("Share distribution verified successfully");
        Ok(())
    }
    
    /// Handle commitment verification
    async fn handle_commitment_verification(
        &self,
        sender_id: ShareId,
        commitment: Vec<u8>,
        value: Vec<u8>,
        randomness: Vec<u8>,
        curve_type: CurveType,
    ) -> Result<()> {
        tracing::info!("Verifying commitment from participant {}", sender_id);
        
        let pedersen = PedersenCommitment::new(curve_type)?;
        let curve = crate::curve::create_curve(curve_type);
        let value_scalar = curve.scalar_from_bytes(&value)?;
        
        let is_valid = pedersen.verify(&commitment, &value_scalar, &randomness)?;
        
        let response = NetworkMessage::CommitmentVerificationResponse {
            sender_id: self.id,
            commitment,
            is_valid,
        };
        
        self.send_to(sender_id, response).await?;
        Ok(())
    }
    
    /// Handle proof verification
    async fn handle_proof_verification(
        &self,
        sender_id: ShareId,
        proof: ZeroKnowledgeProof,
    ) -> Result<()> {
        tracing::info!("Verifying proof from participant {}", sender_id);
        
        let pedersen = PedersenCommitment::new(proof.curve_type)?;
        let is_valid = proof.verify(&pedersen)?;
        
        let response = NetworkMessage::ProofVerificationResponse {
            sender_id: self.id,
            proof_commitment: proof.commitment,
            is_valid,
        };
        
        self.send_to(sender_id, response).await?;
        Ok(())
    }
    
    /// Handle secret reconstruction
    async fn handle_secret_reconstruction(
        &self,
        sender_id: ShareId,
        shares: Vec<Share>,
        curve_type: CurveType,
    ) -> Result<()> {
        tracing::info!("Reconstructing secret from participant {}", sender_id);
        
        let params = crate::types::SharingParams {
            curve_type,
            threshold: shares.len(),
            participants: shares.len(),
        };
        
        let laurent = LaurentSeries::new(&params)?;
        let result = laurent.reconstruct_secret(&shares)?;
        
        let response = NetworkMessage::SecretReconstructionResponse {
            sender_id: self.id,
            secret: result.secret,
            participants_used: result.participants_used,
            is_valid: result.valid,
        };
        
        self.send_to(sender_id, response).await?;
        Ok(())
    }
    
    /// Handle heartbeat
    async fn handle_heartbeat(&self, sender_id: ShareId, timestamp: u64) -> Result<()> {
        let mut participants = self.participants.write().await;
        if let Some(participant) = participants.get_mut(&sender_id) {
            participant.last_heartbeat = timestamp;
            participant.is_online = true;
        }
        Ok(())
    }
}

/// Network coordinator for z-MPC protocol
#[derive(Clone)]
pub struct NetworkCoordinator {
    pub node: NetworkNode,
    pub laurent_series: Option<LaurentSeries>,
    pub pedersen: Option<PedersenCommitment>,
}

impl NetworkCoordinator {
    /// Create new network coordinator
    pub fn new(node: NetworkNode) -> Self {
        Self {
            node,
            laurent_series: None,
            pedersen: None,
        }
    }
    
    /// Initialize z-MPC protocol
    pub async fn initialize_protocol(&mut self, params: crate::types::SharingParams) -> Result<()> {
        self.laurent_series = Some(LaurentSeries::new(&params)?);
        self.pedersen = Some(PedersenCommitment::new(params.curve_type)?);
        
        tracing::info!("z-MPC protocol initialized for curve: {}", params.curve_type);
        Ok(())
    }
    
    /// Distribute shares to all participants
    pub async fn distribute_shares(&self) -> Result<()> {
        let laurent = self.laurent_series.as_ref()
            .ok_or_else(|| Error::InvalidInput("Protocol not initialized".to_string()))?;
        
        let shares = laurent.generate_shares()?;
        let pedersen = self.pedersen.as_ref().unwrap();
        let committed_shares = crate::pedersen::utils::commit_all_shares(&shares, laurent.curve_type)?;
        
        // Generate proofs for all shares
        let mut proofs = Vec::new();
        for (share, committed_share) in shares.iter().zip(committed_shares.iter()) {
            let proof = crate::zkp::utils::prove_committed_share(
                pedersen,
                share,
                &committed_share.randomness,
                laurent.curve_type,
            )?;
            proofs.push(proof);
        }
        
        let message = NetworkMessage::ShareDistribution {
            sender_id: self.node.id,
            shares,
            commitments: committed_shares,
            proofs,
            curve_type: laurent.curve_type,
        };
        
        self.node.broadcast(message).await?;
        Ok(())
    }
    
    /// Run network node
    pub async fn run(&mut self) -> Result<()> {
        tracing::info!("Starting network node on {}", self.node.address);
        
        while let Some(message) = self.node.message_receiver.recv().await {
            self.node.process_message(message).await?;
        }
        
        Ok(())
    }
    
    /// Start HTTP server for network communication
    pub async fn start_http_server(&self) -> Result<()> {
        let app_state = Arc::new(AppState {
            node_id: self.node.id,
            participants: self.node.participants.clone(),
            curve_type: self.node.curve_type,
        });
        
        let app = Router::new()
            .route("/health", get(health_check))
            .route("/shares", post(receive_shares))
            .route("/commitment", post(verify_commitment))
            .route("/proof", post(verify_proof))
            .route("/reconstruct", post(reconstruct_secret))
            .route("/heartbeat", post(receive_heartbeat))
            .with_state(app_state);
        
        tracing::info!("Starting HTTP server on {}", self.node.address);
        
        let listener = tokio::net::TcpListener::bind(self.node.address).await
            .map_err(|e| Error::Internal(format!("Failed to bind to {}: {}", self.node.address, e)))?;
        
        axum::serve(listener, app).await
            .map_err(|e| Error::Internal(format!("HTTP server error: {}", e)))?;
        
        Ok(())
    }
}

/// Application state for HTTP server
#[derive(Clone)]
struct AppState {
    node_id: ShareId,
    participants: Arc<RwLock<HashMap<ShareId, Participant>>>,
    curve_type: CurveType,
}

/// HTTP endpoint handlers
async fn health_check(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let response = serde_json::json!({
        "node_id": state.node_id,
        "curve_type": state.curve_type.to_string(),
        "timestamp": timestamp,
        "status": "healthy"
    });
    
    (StatusCode::OK, Json(response))
}

async fn receive_shares(
    State(state): State<Arc<AppState>>,
    Json(message): Json<NetworkMessage>,
) -> (StatusCode, Json<serde_json::Value>) {
    match message {
        NetworkMessage::ShareDistribution { sender_id, shares, commitments, proofs, curve_type } => {
            tracing::info!("Received shares from participant {}", sender_id);
            
            // Verify commitments and proofs
            match verify_share_distribution(&commitments, &proofs, curve_type).await {
                Ok(_) => {
                    let response = serde_json::json!({
                        "status": "success",
                        "message": "Shares received and verified",
                        "sender_id": sender_id,
                        "shares_count": shares.len()
                    });
                    (StatusCode::OK, Json(response))
                }
                Err(e) => {
                    let response = serde_json::json!({
                        "status": "error",
                        "message": e.to_string(),
                        "sender_id": sender_id
                    });
                    (StatusCode::BAD_REQUEST, Json(response))
                }
            }
        }
        _ => {
            let response = serde_json::json!({
                "status": "error",
                "message": "Invalid message type"
            });
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

async fn verify_commitment(
    State(state): State<Arc<AppState>>,
    Json(message): Json<NetworkMessage>,
) -> (StatusCode, Json<serde_json::Value>) {
    match message {
        NetworkMessage::CommitmentVerification { sender_id, commitment, value, randomness, curve_type } => {
            tracing::info!("Verifying commitment from participant {}", sender_id);
            
            match verify_commitment_internal(&commitment, &value, &randomness, curve_type).await {
                Ok(is_valid) => {
                    let response = serde_json::json!({
                        "status": "success",
                        "sender_id": sender_id,
                        "commitment": hex::encode(&commitment),
                        "is_valid": is_valid
                    });
                    (StatusCode::OK, Json(response))
                }
                Err(e) => {
                    let response = serde_json::json!({
                        "status": "error",
                        "message": e.to_string(),
                        "sender_id": sender_id
                    });
                    (StatusCode::BAD_REQUEST, Json(response))
                }
            }
        }
        _ => {
            let response = serde_json::json!({
                "status": "error",
                "message": "Invalid message type"
            });
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

async fn verify_proof(
    State(state): State<Arc<AppState>>,
    Json(message): Json<NetworkMessage>,
) -> (StatusCode, Json<serde_json::Value>) {
    match message {
        NetworkMessage::ProofVerification { sender_id, proof } => {
            tracing::info!("Verifying proof from participant {}", sender_id);
            
            match verify_proof_internal(&proof).await {
                Ok(is_valid) => {
                    let response = serde_json::json!({
                        "status": "success",
                        "sender_id": sender_id,
                        "proof_commitment": hex::encode(&proof.commitment),
                        "is_valid": is_valid
                    });
                    (StatusCode::OK, Json(response))
                }
                Err(e) => {
                    let response = serde_json::json!({
                        "status": "error",
                        "message": e.to_string(),
                        "sender_id": sender_id
                    });
                    (StatusCode::BAD_REQUEST, Json(response))
                }
            }
        }
        _ => {
            let response = serde_json::json!({
                "status": "error",
                "message": "Invalid message type"
            });
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

async fn reconstruct_secret(
    State(state): State<Arc<AppState>>,
    Json(message): Json<NetworkMessage>,
) -> (StatusCode, Json<serde_json::Value>) {
    match message {
        NetworkMessage::SecretReconstruction { sender_id, shares, curve_type } => {
            tracing::info!("Reconstructing secret from participant {}", sender_id);
            
            match reconstruct_secret_internal(&shares, curve_type).await {
                Ok(result) => {
                    let response = serde_json::json!({
                        "status": "success",
                        "sender_id": sender_id,
                        "secret": hex::encode(&result.secret),
                        "participants_used": result.participants_used,
                        "is_valid": result.valid
                    });
                    (StatusCode::OK, Json(response))
                }
                Err(e) => {
                    let response = serde_json::json!({
                        "status": "error",
                        "message": e.to_string(),
                        "sender_id": sender_id
                    });
                    (StatusCode::BAD_REQUEST, Json(response))
                }
            }
        }
        _ => {
            let response = serde_json::json!({
                "status": "error",
                "message": "Invalid message type"
            });
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

async fn receive_heartbeat(
    State(state): State<Arc<AppState>>,
    Json(message): Json<NetworkMessage>,
) -> (StatusCode, Json<serde_json::Value>) {
    match message {
        NetworkMessage::Heartbeat { sender_id, timestamp } => {
            tracing::debug!("Received heartbeat from participant {}", sender_id);
            
            // Update participant status
            let mut participants = state.participants.write().await;
            if let Some(participant) = participants.get_mut(&sender_id) {
                participant.last_heartbeat = timestamp;
                participant.is_online = true;
            }
            
            let response = serde_json::json!({
                "status": "success",
                "sender_id": sender_id,
                "timestamp": timestamp
            });
            (StatusCode::OK, Json(response))
        }
        _ => {
            let response = serde_json::json!({
                "status": "error",
                "message": "Invalid message type"
            });
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

/// Internal verification functions
async fn verify_share_distribution(
    commitments: &[CommittedShare],
    proofs: &[ZeroKnowledgeProof],
    curve_type: CurveType,
) -> Result<()> {
    let pedersen = PedersenCommitment::new(curve_type)?;
    
    // Verify commitments
    for committed_share in commitments {
        if !committed_share.verify(curve_type)? {
            return Err(Error::CommitmentError("Invalid commitment".to_string()));
        }
    }
    
    // Verify proofs
    for proof in proofs {
        if !proof.verify(&pedersen)? {
            return Err(Error::ZKProofError("Invalid proof".to_string()));
        }
    }
    
    Ok(())
}

async fn verify_commitment_internal(
    commitment: &[u8],
    value: &[u8],
    randomness: &[u8],
    curve_type: CurveType,
) -> Result<bool> {
    let pedersen = PedersenCommitment::new(curve_type)?;
    let curve = crate::curve::create_curve(curve_type);
    let value_scalar = curve.scalar_from_bytes(value)?;
    
    pedersen.verify(commitment, &value_scalar, randomness)
}

async fn verify_proof_internal(proof: &ZeroKnowledgeProof) -> Result<bool> {
    let pedersen = PedersenCommitment::new(proof.curve_type)?;
    proof.verify(&pedersen)
}

async fn reconstruct_secret_internal(
    shares: &[Share],
    curve_type: CurveType,
) -> Result<crate::types::ReconstructionResult> {
    let params = crate::types::SharingParams {
        curve_type,
        threshold: shares.len(),
        participants: shares.len(),
    };
    
    let laurent = LaurentSeries::new(&params)?;
    laurent.reconstruct_secret(shares)
}

/// Utility functions for network operations
pub mod utils {
    use super::*;
    
    /// Create test network with multiple nodes
    pub async fn create_test_network(
        num_participants: usize,
        curve_type: CurveType,
    ) -> Result<Vec<NetworkCoordinator>> {
        let mut coordinators = Vec::new();
        
        for i in 1..=num_participants {
            let address: SocketAddr = format!("127.0.0.1:{}", 8000 + i).parse()?;
            let node = NetworkNode::new(i as ShareId, address, curve_type);
            let mut coordinator = NetworkCoordinator::new(node);
            
            // Add other participants
            for j in 1..=num_participants {
                if i != j {
                    let other_address: SocketAddr = format!("127.0.0.1:{}", 8000 + j).parse()?;
                    let participant = Participant {
                        id: j as ShareId,
                        address: other_address,
                        curve_type,
                        is_online: true,
                        last_heartbeat: 0,
                    };
                    coordinator.node.add_participant(participant).await?;
                }
            }
            
            coordinators.push(coordinator);
        }
        
        Ok(coordinators)
    }
    
    /// Run distributed z-MPC protocol
    pub async fn run_distributed_protocol(
        coordinators: &mut [NetworkCoordinator],
        threshold: usize,
    ) -> Result<()> {
        let curve_type = coordinators[0].node.curve_type;
        let participants = coordinators.len();
        
        let params = crate::types::SharingParams {
            curve_type,
            threshold,
            participants,
        };
        
        // Initialize all coordinators
        for coordinator in coordinators.iter_mut() {
            coordinator.initialize_protocol(params.clone()).await?;
        }
        
        // Dealer distributes shares
        coordinators[0].distribute_shares().await?;
        
        tracing::info!("Distributed z-MPC protocol completed");
        Ok(())
    }
    
    /// Start all HTTP servers for network coordinators
    pub async fn start_all_servers(coordinators: &[NetworkCoordinator]) -> Result<Vec<tokio::task::JoinHandle<Result<()>>>> {
        let mut handles = Vec::new();
        
        for coordinator in coordinators {
            let coordinator_clone = coordinator.clone();
            let handle = tokio::spawn(async move {
                coordinator_clone.start_http_server().await
            });
            handles.push(handle);
        }
        
        Ok(handles)
    }
} 