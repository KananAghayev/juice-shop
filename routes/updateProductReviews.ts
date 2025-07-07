/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ObjectId } from 'mongodb'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)

    // 🔒 Validate and sanitize ObjectId
    let reviewId: ObjectId
    try {
      reviewId = new ObjectId(req.body.id)
    } catch (error) {
      return res.status(400).json({ error: 'Invalid review ID format.' })
    }

    const sanitizedMessage = typeof req.body.message === 'string' ? req.body.message : ''

    db.reviewsCollection.update(
      { _id: reviewId },
      { $set: { message: sanitizedMessage } },
      { multi: false } // prevent mass update
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => result.modified > 1)
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => {
          return user?.data &&
            result.original[0] &&
            result.original[0].author !== user.data.email &&
            result.modified === 1
        })
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
