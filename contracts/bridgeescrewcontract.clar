;; title: BridgeEscrow
;; version: 2.0.0
;; summary: Trust-minimized escrow for BTC payments with enhanced security and on-chain dispute resolution
;; description: Cross-chain escrow system using sBTC with milestone-based releases,
;;              multi-sig conditions, timeouts, arbitrator challenges, fee sharing,
;;              and comprehensive security protections

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

;; Enhanced security error constants
(define-constant ERR_REENTRANCY (err u409))
(define-constant ERR_RATE_LIMITED (err u410))
(define-constant ERR_INVALID_INPUT (err u411))
(define-constant ERR_ARBITRATOR_NOT_STAKED (err u412))
(define-constant ERR_INSUFFICIENT_STAKE (err u413))
(define-constant ERR_OVERFLOW (err u414))
(define-constant ERR_UNDERFLOW (err u415))
(define-constant ERR_MAX_ESCROWS_EXCEEDED (err u416))
(define-constant ERR_INVALID_AMOUNT (err u417))
(define-constant ERR_BLACKLISTED (err u418))
(define-constant ERR_EMERGENCY_ONLY (err u419))

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

;; Security configuration
(define-constant MAX_ESCROWS_PER_USER u10) ;; Maximum escrows per user
(define-constant MIN_ESCROW_AMOUNT u1000) ;; Minimum escrow amount in satoshis
(define-constant MAX_ESCROW_AMOUNT u2100000000000) ;; Maximum escrow amount (21 BTC)
(define-constant MIN_ARBITRATOR_STAKE u1000000) ;; Minimum arbitrator stake in satoshis
(define-constant RATE_LIMIT_WINDOW u10) ;; Rate limit window in blocks
(define-constant MAX_ACTIONS_PER_WINDOW u3) ;; Max actions per rate limit window
(define-constant MAX_MILESTONES u100) ;; Maximum milestones per escrow

;; data vars
(define-data-var next-escrow-id uint u1)
(define-data-var treasury-address principal CONTRACT_OWNER)
(define-data-var emergency-pause bool false)
(define-data-var reentrancy-lock bool false)
(define-data-var max-escrow-amount uint MAX_ESCROW_AMOUNT)
(define-data-var min-escrow-amount uint MIN_ESCROW_AMOUNT)

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

;; Security maps
(define-map reentrancy-guard
  principal
  bool
)

(define-map rate-limit
  principal
  { last-action: uint, action-count: uint }
)

(define-map blacklist
  principal
  bool
)

(define-map arbitrator-stakes
  principal
  uint
)

(define-map user-escrow-count
  principal
  uint
)


;; Security helper functions

;; Check reentrancy protection
(define-private (check-reentrancy)
  (if (var-get reentrancy-lock)
    ERR_REENTRANCY
    (begin
      (var-set reentrancy-lock true)
      (ok true)
    )
  )
)

;; Release reentrancy lock
(define-private (release-reentrancy)
  (var-set reentrancy-lock false)
)

;; Check rate limiting
(define-private (check-rate-limit (user principal))
  (let 
    (
      (current-block stacks-block-height)
      (rate-data (default-to { last-action: u0, action-count: u0 } (map-get? rate-limit user)))
    )
    (if (or 
          (is-eq (get last-action rate-data) u0)
          (> (- current-block (get last-action rate-data)) RATE_LIMIT_WINDOW))
      (begin
        (map-set rate-limit user { last-action: current-block, action-count: u1 })
        (ok true)
      )
      (if (< (get action-count rate-data) MAX_ACTIONS_PER_WINDOW)
        (begin
          (map-set rate-limit user { 
            last-action: (get last-action rate-data), 
            action-count: (+ (get action-count rate-data) u1) 
          })
          (ok true)
        )
        ERR_RATE_LIMITED
      )
    )
  )
)

;; Check if user is blacklisted
(define-private (check-blacklist (user principal))
  (if (default-to false (map-get? blacklist user))
    ERR_BLACKLISTED
    (ok true)
  )
)

;; Validate amount bounds
(define-private (validate-amount (amount uint))
  (if (and (>= amount (var-get min-escrow-amount)) (<= amount (var-get max-escrow-amount)))
    (ok true)
    ERR_INVALID_AMOUNT
  )
)

;; Check arbitrator stake
(define-private (check-arbitrator-stake (arbitrator principal))
  (let ((stake (default-to u0 (map-get? arbitrator-stakes arbitrator))))
    (if (>= stake MIN_ARBITRATOR_STAKE)
      (ok true)
      ERR_ARBITRATOR_NOT_STAKED
    )
  )
)

;; Check user escrow limit
(define-private (check-escrow-limit (user principal))
  (let ((count (default-to u0 (map-get? user-escrow-count user))))
    (if (< count MAX_ESCROWS_PER_USER)
      (ok true)
      ERR_MAX_ESCROWS_EXCEEDED
    )
  )
)

;; Safe arithmetic operations
(define-private (safe-add (a uint) (b uint))
  (let ((result (+ a b)))
    (if (or (< result a) (< result b))
      ERR_OVERFLOW
      (ok result)
    )
  )
)

(define-private (safe-multiply (a uint) (b uint))
  (if (or (is-eq a u0) (is-eq b u0))
    (ok u0)
    (let ((result (* a b)))
      (if (or (< (/ result a) b) (< (/ result b) a))
        ERR_OVERFLOW
        (ok result)
      )
    )
  )
)

;; public functions

;; Create new escrow with milestone configuration
(define-public (create-escrow 
  (seller principal) 
  (arbitrator principal) 
  (amount uint) 
  (total-milestones uint))
  (begin
    ;; Security checks
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    (try! (check-blacklist tx-sender))
    (try! (check-blacklist seller))
    (try! (check-blacklist arbitrator))
    (try! (check-escrow-limit tx-sender))
    (try! (check-arbitrator-stake arbitrator))
    (try! (validate-amount amount))
    
    (let 
      (
        (escrow-id (var-get next-escrow-id))
        (fee (calculate-total-fee amount))
        (timeout-block (unwrap! (safe-add stacks-block-height DELIVERY_TIMEOUT) ERR_OVERFLOW))
      )
      (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
      (asserts! (> amount u0) ERR_INSUFFICIENT_FUNDS)
      (asserts! (and (> total-milestones u0) (<= total-milestones MAX_MILESTONES)) ERR_INVALID_MILESTONE)
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
          created-at: stacks-block-height,
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
      (var-set next-escrow-id (unwrap! (safe-add escrow-id u1) ERR_OVERFLOW))
      (update-user-stats tx-sender u1 u0 u0)
      (update-user-escrow-count tx-sender u1)
      
      (print {
        event: "escrow-created",
        escrow-id: escrow-id,
        buyer: tx-sender,
        seller: seller,
        arbitrator: arbitrator,
        amount: amount,
        milestones: total-milestones
      })
      
      ;; Release reentrancy lock
      (release-reentrancy)
      
      (ok escrow-id)
    )
  )
)

;; Fund escrow (buyer deposits sBTC)
(define-public (fund-escrow (escrow-id uint))
  (begin
    ;; Security checks
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    (try! (check-blacklist tx-sender))
    
    (let 
      (
        (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
        (total-amount (unwrap! (safe-add (get amount escrow) (get fee escrow)) ERR_OVERFLOW))
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
          funded-at: (some stacks-block-height)
        })
      )
      
      (print {
        event: "escrow-funded",
        escrow-id: escrow-id,
        amount: total-amount
      })
      
      ;; Release reentrancy lock
      (release-reentrancy)
      
      (ok true)
    )
  )
)

;; Complete milestone (seller reports delivery progress)
(define-public (complete-milestone (escrow-id uint))
  (begin
    ;; Security checks
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    (try! (check-blacklist tx-sender))
    
    (let 
      (
        (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
        (new-milestones (unwrap! (safe-add (get milestones-completed escrow) u1) ERR_OVERFLOW))
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
                           (some stacks-block-height)
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
      
      ;; Release reentrancy lock
      (release-reentrancy)
      
      (ok true)
    )
  )
)

;; Release escrow funds (buyer confirms satisfaction or multi-sig release)
(define-public (release-escrow (escrow-id uint))
  (begin
    ;; Security checks
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    (try! (check-blacklist tx-sender))
    
    (let 
      (
        (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
        (seller (get seller escrow))
        (amount (get amount escrow))
        (fee (get fee escrow))
        (treasury-fee (unwrap! (safe-multiply fee TREASURY_FEE_BPS) ERR_OVERFLOW))
        (arbitrator-fee (unwrap! (safe-multiply fee ARBITRATOR_FEE_BPS) ERR_OVERFLOW))
        (treasury-fee-calculated (/ treasury-fee u10000))
        (arbitrator-fee-calculated (/ arbitrator-fee u10000))
        (total-fees (unwrap! (safe-add treasury-fee-calculated arbitrator-fee-calculated) ERR_OVERFLOW))
        (remaining-fee (if (> total-fees fee) u0 (- fee total-fees)))
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
      (try! (as-contract (ft-transfer? sbtc treasury-fee-calculated tx-sender (var-get treasury-address))))
      
      ;; Transfer arbitrator fee if arbitrated
      (if (is-eq (get state escrow) STATE_ARBITRATED)
        (try! (as-contract (ft-transfer? sbtc arbitrator-fee-calculated tx-sender (get arbitrator escrow))))
        (try! (as-contract (ft-transfer? sbtc arbitrator-fee-calculated tx-sender (var-get treasury-address))))
      )
      
      ;; Transfer remaining fee to treasury
      (if (> remaining-fee u0)
        (try! (as-contract (ft-transfer? sbtc remaining-fee tx-sender (var-get treasury-address))))
        true
      )
      
      ;; Update escrow state
      (map-set escrows escrow-id
        (merge escrow { state: STATE_COMPLETED })
      )
      
      ;; Update user stats
      (update-user-stats (get buyer escrow) u0 u1 u0)
      (update-user-stats seller u0 u1 u0)
      (update-user-escrow-count (get buyer escrow) u0)
      
      (print {
        event: "escrow-released",
        escrow-id: escrow-id,
        seller: seller,
        amount: amount
      })
      
      ;; Release reentrancy lock
      (release-reentrancy)
      
      (ok true)
    )
  )
)

;; Dispute escrow (buyer raises dispute)
(define-public (dispute-escrow (escrow-id uint) (reason (string-ascii 256)))
  (begin
    ;; Security checks
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    (try! (check-blacklist tx-sender))
    
    (let 
      (
        (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
        (dispute-timeout (unwrap! (safe-add (get timeout-at escrow) DISPUTE_TIMEOUT) ERR_OVERFLOW))
      )
      (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
      (asserts! (is-eq tx-sender (get buyer escrow)) ERR_NOT_AUTHORIZED)
      (asserts! (or 
        (is-eq (get state escrow) STATE_FUNDED)
        (is-eq (get state escrow) STATE_DELIVERED)
      ) ERR_INVALID_STATE)
      (asserts! (< stacks-block-height dispute-timeout) ERR_TIMEOUT_NOT_REACHED)
      
      ;; Update escrow state
      (map-set escrows escrow-id
        (merge escrow {
          state: STATE_DISPUTED,
          disputed-at: (some stacks-block-height),
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
      
      ;; Release reentrancy lock
      (release-reentrancy)
      
      (ok true)
    )
  )
)

;; Arbitrator resolves dispute
(define-public (resolve-dispute (escrow-id uint) (release-to-seller bool))
  (begin
    ;; Security checks
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    (try! (check-blacklist tx-sender))
    
    (let 
      (
        (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
        (disputed-at (unwrap! (get disputed-at escrow) ERR_INVALID_STATE))
        (challenge-deadline (unwrap! (safe-add disputed-at CHALLENGE_WINDOW) ERR_OVERFLOW))
      )
      (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
      (asserts! (is-eq tx-sender (get arbitrator escrow)) ERR_NOT_AUTHORIZED)
      (asserts! (is-eq (get state escrow) STATE_DISPUTED) ERR_INVALID_STATE)
      (asserts! (< stacks-block-height challenge-deadline) ERR_CHALLENGE_WINDOW_EXPIRED)
      
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
      
      ;; Release reentrancy lock
      (release-reentrancy)
      
      (ok true)
    )
  )
)

;; Refund escrow (timeout or dispute resolution)
(define-public (refund-escrow (escrow-id uint))
  (begin
    ;; Security checks
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    (try! (check-blacklist tx-sender))
    
    (let 
      (
        (escrow (unwrap! (map-get? escrows escrow-id) ERR_ESCROW_NOT_FOUND))
        (buyer (get buyer escrow))
        (refund-amount (unwrap! (safe-add (get amount escrow) (get fee escrow)) ERR_OVERFLOW))
      )
      (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
      (asserts! (or
        ;; Timeout refund
        (and (> stacks-block-height (get timeout-at escrow)) (is-eq (get state escrow) STATE_FUNDED))
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
      
      ;; Update user stats
      (update-user-escrow-count buyer u0)
      
      (print {
        event: "escrow-refunded",
        escrow-id: escrow-id,
        buyer: buyer,
        amount: refund-amount
      })
      
      ;; Release reentrancy lock
      (release-reentrancy)
      
      (ok true)
    )
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

;; Stake as arbitrator (arbitrator only)
(define-public (stake-as-arbitrator (amount uint))
  (begin
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    (try! (check-blacklist tx-sender))
    (try! (validate-amount amount))
    
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    (asserts! (>= amount MIN_ARBITRATOR_STAKE) ERR_INSUFFICIENT_STAKE)
    
    ;; Transfer stake to contract
    (try! (ft-transfer? sbtc amount tx-sender (as-contract tx-sender)))
    
    ;; Update arbitrator stake
    (let ((current-stake (default-to u0 (map-get? arbitrator-stakes tx-sender))))
      (map-set arbitrator-stakes tx-sender (unwrap! (safe-add current-stake amount) ERR_OVERFLOW))
    )
    
    (print {
      event: "arbitrator-staked",
      arbitrator: tx-sender,
      amount: amount
    })
    
    (release-reentrancy)
    (ok true)
  )
)

;; Unstake as arbitrator (arbitrator only)
(define-public (unstake-as-arbitrator (amount uint))
  (begin
    (try! (check-reentrancy))
    (try! (check-rate-limit tx-sender))
    
    (asserts! (not (var-get emergency-pause)) ERR_NOT_AUTHORIZED)
    
    (let ((current-stake (default-to u0 (map-get? arbitrator-stakes tx-sender))))
      (asserts! (>= current-stake amount) ERR_INSUFFICIENT_STAKE)
      (asserts! (>= (- current-stake amount) MIN_ARBITRATOR_STAKE) ERR_INSUFFICIENT_STAKE)
      
      ;; Update arbitrator stake
      (map-set arbitrator-stakes tx-sender (- current-stake amount))
      
      ;; Transfer stake back to arbitrator
      (try! (as-contract (ft-transfer? sbtc amount tx-sender tx-sender)))
      
      (print {
        event: "arbitrator-unstaked",
        arbitrator: tx-sender,
        amount: amount
      })
    )
    
    (release-reentrancy)
    (ok true)
  )
)

;; Blacklist user (owner only)
(define-public (blacklist-user (user principal) (blacklisted bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (map-set blacklist user blacklisted)
    (print { event: "user-blacklisted", user: user, blacklisted: blacklisted })
    (ok true)
  )
)

;; Update escrow limits (owner only)
(define-public (set-escrow-limits (min-amount uint) (max-amount uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (asserts! (and (> min-amount u0) (< min-amount max-amount)) ERR_INVALID_INPUT)
    (var-set min-escrow-amount min-amount)
    (var-set max-escrow-amount max-amount)
    (print { event: "escrow-limits-updated", min-amount: min-amount, max-amount: max-amount })
    (ok true)
  )
)

;; Emergency withdrawal (owner only, when paused)
(define-public (emergency-withdraw (amount uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (asserts! (var-get emergency-pause) ERR_EMERGENCY_ONLY)
    (try! (as-contract (ft-transfer? sbtc amount tx-sender (var-get treasury-address))))
    (print { event: "emergency-withdrawal", amount: amount })
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
      (< stacks-block-height (+ (get timeout-at escrow) DISPUTE_TIMEOUT))
    ))
    ERR_ESCROW_NOT_FOUND
  )
)

;; Check if escrow can be refunded
(define-read-only (can-refund-escrow (escrow-id uint))
  (match (map-get? escrows escrow-id)
    escrow (ok (or
      (and (> stacks-block-height (get timeout-at escrow)) (is-eq (get state escrow) STATE_FUNDED))
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
    arbitrator-fee-bps: ARBITRATOR_FEE_BPS,
    min-escrow-amount: (var-get min-escrow-amount),
    max-escrow-amount: (var-get max-escrow-amount),
    min-arbitrator-stake: MIN_ARBITRATOR_STAKE
  })
)

;; Get arbitrator stake
(define-read-only (get-arbitrator-stake (arbitrator principal))
  (ok (default-to u0 (map-get? arbitrator-stakes arbitrator)))
)

;; Check if user is blacklisted
(define-read-only (is-user-blacklisted (user principal))
  (ok (default-to false (map-get? blacklist user)))
)

;; Get user escrow count
(define-read-only (get-user-escrow-count (user principal))
  (ok (default-to u0 (map-get? user-escrow-count user)))
)

;; Get rate limit info
(define-read-only (get-rate-limit-info (user principal))
  (ok (default-to { last-action: u0, action-count: u0 } (map-get? rate-limit user)))
)


;; private functions

;; Calculate total fee for escrow
(define-private (calculate-total-fee (amount uint))
  (+ 
    (/ (* amount TREASURY_FEE_BPS) u10000)
    (/ (* amount ARBITRATOR_FEE_BPS) u10000)
  )
)

;; Update user statistics
(define-private (update-user-stats (user principal) (created uint) (completed uint) (disputes uint))
  (let 
    (
      (current-stats (default-to 
        { escrows-created: u0, escrows-completed: u0, disputes: u0 }
        (map-get? user-stats user)
      ))
    )
    (map-set user-stats user {
      escrows-created: (+ (get escrows-created current-stats) created),
      escrows-completed: (+ (get escrows-completed current-stats) completed),
      disputes: (+ (get disputes current-stats) disputes)
    })
  )
)

;; Update arbitrator reputation
(define-private (update-arbitrator-reputation (arbitrator principal) (successful bool))
  (let 
    (
      (current-rep (default-to
        { total-cases: u0, successful-resolutions: u0, stake: u0 }
        (map-get? arbitrator-reputation arbitrator)
      ))
    )
    (map-set arbitrator-reputation arbitrator {
      total-cases: (+ (get total-cases current-rep) u1),
      successful-resolutions: (+ (get successful-resolutions current-rep) (if successful u1 u0)),
      stake: (get stake current-rep)
    })
  )
)

;; Update user escrow count
(define-private (update-user-escrow-count (user principal) (increment uint))
  (let ((current-count (default-to u0 (map-get? user-escrow-count user))))
    (if (is-eq increment u0)
      ;; Decrement count
      (map-set user-escrow-count user (if (> current-count u0) (- current-count u1) u0))
      ;; Increment count
      (map-set user-escrow-count user (+ current-count increment))
    )
  )
)