;; title: BridgeEscrow
;; version: 1.0.0
;; summary: Trust-minimized escrow for BTC payments with on-chain dispute resolution
;; description: Cross-chain escrow system using sBTC with milestone-based releases,
;;              multi-sig conditions, timeouts, arbitrator challenges, and fee sharing

;; traits
(define-trait escrow-trait
  (
    (create-escrow (principal principal uint uint uint) (response uint uint))
    (release-escrow (uint) (response bool uint))
    (dispute-escrow (uint) (response bool uint))
  )
)

;; token definitions
(define-fungible-token sbtc)

;; constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u401))
(define-constant ERR_ESCROW_NOT_FOUND (err u404))
(define-constant ERR_INVALID_STATE (err u400))
(define-constant ERR_INSUFFICIENT_FUNDS (err u402))
(define-constant ERR_TIMEOUT_NOT_REACHED (err u403))
(define-constant ERR_ALREADY_DISPUTED (err u405))
(define-constant ERR_CHALLENGE_WINDOW_EXPIRED (err u406))
(define-constant ERR_INVALID_MILESTONE (err u407))
(define-constant ERR_TRANSFER_FAILED (err u408))

;; Escrow states
(define-constant STATE_PENDING u0)
(define-constant STATE_FUNDED u1)
(define-constant STATE_DELIVERED u2)
(define-constant STATE_COMPLETED u3)
(define-constant STATE_DISPUTED u4)
(define-constant STATE_REFUNDED u5)
(define-constant STATE_ARBITRATED u6)

;; Fee configuration (basis points - 100 = 1%)
(define-constant TREASURY_FEE_BPS u250) ;; 2.5%
(define-constant ARBITRATOR_FEE_BPS u100) ;; 1%

;; Timeout periods (blocks)
(define-constant DELIVERY_TIMEOUT u2016) ;; ~2 weeks
(define-constant DISPUTE_TIMEOUT u1008) ;; ~1 week
(define-constant CHALLENGE_WINDOW u144) ;; ~1 day

;; data vars
(define-data-var next-escrow-id uint u1)
(define-data-var treasury-address principal CONTRACT_OWNER)
(define-data-var emergency-pause bool false)

;; data maps
(define-map escrows
  uint
  {
    buyer: principal,
    seller: principal,
    arbitrator: principal,
    amount: uint,
    fee: uint,
    state: uint,
    created-at: uint,
    funded-at: (optional uint),
    delivered-at: (optional uint),
    disputed-at: (optional uint),
    timeout-at: uint,
    dispute-reason: (optional (string-ascii 256)),
    milestones-completed: uint,
    total-milestones: uint
  }
)

(define-map escrow-signatures
  { escrow-id: uint, signer: principal }
  { signed: bool, signed-at: uint }
)

(define-map arbitrator-reputation
  principal
  { total-cases: uint, successful-resolutions: uint, stake: uint }
)

(define-map user-stats
  principal
  { escrows-created: uint, escrows-completed: uint, disputes: uint }
)
