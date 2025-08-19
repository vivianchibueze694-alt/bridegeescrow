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


;; public functions

;; Create new escrow with milestone configuration
(define-public (create-escrow 
  (seller principal) 
  (arbitrator principal) 
  (amount uint) 
  (total-milestones uint))
  (let 
    (
      (escrow-id (var-get next-escrow-id))
      (fee (calculate-total-fee amount))
      (timeout-block (+ block-height DELIVERY_TIMEOUT))
    )
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    (asserts! (> amount u0) ERR_INSUFFICIENT_FUNDS)
    (asserts! (> total-milestones u0) ERR_INVALID_MILESTONE)
    (asserts! (not (is-eq tx-sender seller)) ERR_NOT_AUTHORIZED)
    (asserts! (not (is-eq tx-sender arbitrator)) ERR_NOT_AUTHORIZED)
    (asserts! (not (is-eq seller arbitrator)) ERR_NOT_AUTHORIZED)
    
    ;; Store escrow details
    (map-set escrows escrow-id
      {
        buyer: tx-sender,
        seller: seller,
        arbitrator: arbitrator,
        amount: amount,
        fee: fee,
        state: STATE_PENDING,
        created-at: block-height,
        funded-at: none,
        delivered-at: none,
        disputed-at: none,
        timeout-at: timeout-block,
        dispute-reason: none,
        milestones-completed: u0,
        total-milestones: total-milestones
      }
    )
    
    ;; Update counters
    (var-set next-escrow-id (+ escrow-id u1))
    (update-user-stats tx-sender u1 u0 u0)
    
    (print {
      event: "escrow-created",
      escrow-id: escrow-id,
      buyer: tx-sender,
      seller: seller,
      arbitrator: arbitrator,
      amount: amount,
      milestones: total-milestones
    })
    
    (ok escrow-id)
  )
)

;; Fund escrow (buyer deposits sBTC)
(define-public (fund-escrow (escrow-id uint))
  (let 
    (
      (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
      (total-amount (+ (get amount escrow) (get fee escrow)))
    )
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    (asserts! (is-eq tx-sender (get buyer escrow)) ERR_NOT_AUTHORIZED)
    (asserts! (is-eq (get state escrow) STATE_PENDING) ERR_INVALID_STATE)
    
    ;; Transfer sBTC from buyer to contract
    (try! (ft-transfer? sbtc total-amount tx-sender (as-contract tx-sender)))
    
    ;; Update escrow state
    (map-set escrows escrow-id
      (merge escrow {
        state: STATE_FUNDED,
        funded-at: (some block-height)
      })
    )
    
    (print {
      event: "escrow-funded",
      escrow-id: escrow-id,
      amount: total-amount
    })
    
    (ok true)
  )
)

;; Complete milestone (seller reports delivery progress)
(define-public (complete-milestone (escrow-id uint))
  (let 
    (
      (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
      (new-milestones (+ (get milestones-completed escrow) u1))
    )
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    (asserts! (is-eq tx-sender (get seller escrow)) ERR_NOT_AUTHORIZED)
    (asserts! (is-eq (get state escrow) STATE_FUNDED) ERR_INVALID_STATE)
    (asserts! (< (get milestones-completed escrow) (get total-milestones escrow)) ERR_INVALID_MILESTONE)
    
    ;; Update milestone progress
    (map-set escrows escrow-id
      (merge escrow {
        milestones-completed: new-milestones,
        delivered-at: (if (is-eq new-milestones (get total-milestones escrow))
                         (some block-height)
                         (get delivered-at escrow)),
        state: (if (is-eq new-milestones (get total-milestones escrow))
                  STATE_DELIVERED
                  STATE_FUNDED)
      })
    )
    
    (print {
      event: "milestone-completed",
      escrow-id: escrow-id,
      milestones-completed: new-milestones,
      total-milestones: (get total-milestones escrow)
    })
    
    (ok true)
  )
)

;; Release escrow funds (buyer confirms satisfaction or multi-sig release)
(define-public (release-escrow (escrow-id uint))
  (let 
    (
      (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
      (seller (get seller escrow))
      (amount (get amount escrow))
      (fee (get fee escrow))
      (treasury-fee (/ (* fee TREASURY_FEE_BPS) u10000))
      (arbitrator-fee (/ (* fee ARBITRATOR_FEE_BPS) u10000))
      (remaining-fee (- fee (+ treasury-fee arbitrator-fee)))
    )
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    (asserts! (or 
      (is-eq tx-sender (get buyer escrow))
      (and (is-eq tx-sender (get arbitrator escrow)) (is-eq (get state escrow) STATE_ARBITRATED))
    ) ERR_NOT_AUTHORIZED)
    (asserts! (or 
      (is-eq (get state escrow) STATE_DELIVERED)
      (is-eq (get state escrow) STATE_ARBITRATED)
    ) ERR_INVALID_STATE)
    
    ;; Transfer funds
    (try! (as-contract (ft-transfer? sbtc amount tx-sender seller)))
    (try! (as-contract (ft-transfer? sbtc treasury-fee tx-sender (var-get treasury-address))))
    
    ;; Transfer arbitrator fee if arbitrated
    (if (is-eq (get state escrow) STATE_ARBITRATED)
      (try! (as-contract (ft-transfer? sbtc arbitrator-fee tx-sender (get arbitrator escrow))))
      (try! (as-contract (ft-transfer? sbtc arbitrator-fee tx-sender (var-get treasury-address))))
    )
    
    ;; Transfer remaining fee to treasury
    (if (> remaining-fee u0)
      (try! (as-contract (ft-transfer? sbtc remaining-fee tx-sender (var-get treasury-address))))
      (ok true)
    )
    
    ;; Update escrow state
    (map-set escrows escrow-id
      (merge escrow { state: STATE_COMPLETED })
    )
    
    ;; Update user stats
    (update-user-stats (get buyer escrow) u0 u1 u0)
    (update-user-stats seller u0 u1 u0)
    
    (print {
      event: "escrow-released",
      escrow-id: escrow-id,
      seller: seller,
      amount: amount
    })
    
    (ok true)
  )
)

;; Dispute escrow (buyer raises dispute)
(define-public (dispute-escrow (escrow-id uint) (reason (string-ascii 256)))
  (let 
    (
      (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
    )
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    (asserts! (is-eq tx-sender (get buyer escrow)) ERR_NOT_AUTHORIZED)
    (asserts! (or 
      (is-eq (get state escrow) STATE_FUNDED)
      (is-eq (get state escrow) STATE_DELIVERED)
    ) ERR_INVALID_STATE)
    (asserts! (< block-height (+ (get timeout-at escrow) DISPUTE_TIMEOUT)) ERR_TIMEOUT_NOT_REACHED)
    
    ;; Update escrow state
    (map-set escrows escrow-id
      (merge escrow {
        state: STATE_DISPUTED,
        disputed-at: (some block-height),
        dispute-reason: (some reason)
      })
    )
    
    ;; Update user stats
    (update-user-stats tx-sender u0 u0 u1)
    
    (print {
      event: "escrow-disputed",
      escrow-id: escrow-id,
      reason: reason
    })
    
    (ok true)
  )
)

;; Arbitrator resolves dispute
(define-public (resolve-dispute (escrow-id uint) (release-to-seller bool))
  (let 
    (
      (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
    )
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    (asserts! (is-eq tx-sender (get arbitrator escrow)) ERR_NOT_AUTHORIZED)
    (asserts! (is-eq (get state escrow) STATE_DISPUTED) ERR_INVALID_STATE)
    (asserts! (< block-height (+ (unwrap! (get disputed-at escrow) ERR_INVALID_STATE) CHALLENGE_WINDOW)) ERR_CHALLENGE_WINDOW_EXPIRED)
    
    ;; Update escrow state
    (map-set escrows escrow-id
      (merge escrow { 
        state: (if release-to-seller STATE_ARBITRATED STATE_REFUNDED)
      })
    )
    
    ;; Update arbitrator reputation
    (update-arbitrator-reputation (get arbitrator escrow) true)
    
    (print {
      event: "dispute-resolved",
      escrow-id: escrow-id,
      arbitrator: (get arbitrator escrow),
      release-to-seller: release-to-seller
    })
    
    (ok true)
  )
)

;; Refund escrow (timeout or dispute resolution)
(define-public (refund-escrow (escrow-id uint))
  (let 
    (
      (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
      (buyer (get buyer escrow))
      (refund-amount (+ (get amount escrow) (get fee escrow)))
    )
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    (asserts! (or
      ;; Timeout refund
      (and (> block-height (get timeout-at escrow)) (is-eq (get state escrow) STATE_FUNDED))
      ;; Dispute refund
      (is-eq (get state escrow) STATE_REFUNDED)
      ;; Emergency refund by owner
      (is-eq tx-sender CONTRACT_OWNER)
    ) ERR_NOT_AUTHORIZED)
    
    ;; Transfer refund to buyer
    (try! (as-contract (ft-transfer? sbtc refund-amount tx-sender buyer)))
    
    ;; Update escrow state
    (map-set escrows escrow-id
      (merge escrow { state: STATE_REFUNDED })
    )
    
    (print {
      event: "escrow-refunded",
      escrow-id: escrow-id,
      buyer: buyer,
      amount: refund-amount
    })
    
    (ok true)
  )
)

;; Emergency pause (owner only)
(define-public (set-emergency-pause (paused bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (var-set emergency-pause paused)
    (print { event: "emergency-pause", paused: paused })
    (ok true)
  )
)

;; Update treasury address (owner only)
(define-public (set-treasury-address (new-treasury principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (var-set treasury-address new-treasury)
    (print { event: "treasury-updated", new-treasury: new-treasury })
    (ok true)
  )
)


;; read only functions

;; Get escrow details
(define-read-only (get-escrow (escrow-id uint))
  (map-get? escrows escrow-id)
)

;; Get escrow state
(define-read-only (get-escrow-state (escrow-id uint))
  (match (map-get? escrows escrow-id)
    escrow (ok (get state escrow))
    ERR_ESCROW_NOT_FOUND
  )
)

;; Get milestone progress
(define-read-only (get-milestone-progress (escrow-id uint))
  (match (map-get? escrows escrow-id)
    escrow (ok {
      completed: (get milestones-completed escrow),
      total: (get total-milestones escrow),
      progress-percent: (/ (* (get milestones-completed escrow) u100) (get total-milestones escrow))
    })
    ERR_ESCROW_NOT_FOUND
  )
)

;; Get user statistics
(define-read-only (get-user-stats (user principal))
  (default-to 
    { escrows-created: u0, escrows-completed: u0, disputes: u0 }
    (map-get? user-stats user)
  )
)

;; Get arbitrator reputation
(define-read-only (get-arbitrator-reputation (arbitrator principal))
  (default-to
    { total-cases: u0, successful-resolutions: u0, stake: u0 }
    (map-get? arbitrator-reputation arbitrator)
  )
)

;; Check if escrow can be released
(define-read-only (can-release-escrow (escrow-id uint))
  (match (map-get? escrows escrow-id)
    escrow (ok (or 
      (is-eq (get state escrow) STATE_DELIVERED)
      (is-eq (get state escrow) STATE_ARBITRATED)
    ))
    ERR_ESCROW_NOT_FOUND
  )
)

;; Check if escrow can be disputed
(define-read-only (can-dispute-escrow (escrow-id uint))
  (match (map-get? escrows escrow-id)
    escrow (ok (and
      (or (is-eq (get state escrow) STATE_FUNDED) (is-eq (get state escrow) STATE_DELIVERED))
      (< block-height (+ (get timeout-at escrow) DISPUTE_TIMEOUT))
    ))
    ERR_ESCROW_NOT_FOUND
  )
)

;; Check if escrow can be refunded
(define-read-only (can-refund-escrow (escrow-id uint))
  (match (map-get? escrows escrow-id)
    escrow (ok (or
      (and (> block-height (get timeout-at escrow)) (is-eq (get state escrow) STATE_FUNDED))
      (is-eq (get state escrow) STATE_REFUNDED)
    ))
    ERR_ESCROW_NOT_FOUND
  )
)

;; Get contract info
(define-read-only (get-contract-info)
  (ok {
    next-escrow-id: (var-get next-escrow-id),
    treasury-address: (var-get treasury-address),
    emergency-pause: (var-get emergency-pause),
    treasury-fee-bps: TREASURY_FEE_BPS,
    arbitrator-fee-bps: ARBITRATOR_FEE_BPS
  })
)
