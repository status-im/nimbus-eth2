type
  UpdateFlag* = enum
    skipBlsValidation
    skipStateRootValidation
    strictVerification
    slotProcessed
    skipLastStateRootCalculation

  UpdateFlags* = set[UpdateFlag]
