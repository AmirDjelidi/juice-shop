/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as models from '../models/index'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    // --- sanitize input length only (not for security, just UX) ---
    let criteria = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    // eslint-disable-next-line @typescript-eslint/no-base-to-string
    criteria = criteria.toString().substring(0, 200)

    console.log(`Searching for products containing '${criteria}'`)

    // --- SAFE: parameterized query ---
    models.sequelize.query(
            `SELECT *
             FROM Products
             WHERE (
                       (name LIKE :search OR description LIKE :search)
                           AND deletedAt IS NULL
                       )
             ORDER BY name`,
            {
              replacements: { search: `%${criteria}%` },
              type: (models.sequelize as any).constructor.QueryTypes.SELECT
            }
    ).then((products: any[]) => {
      const dataString = JSON.stringify(products)

      // -------- original challenge logic (unchanged) --------
      if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) {
        let solved = true
        UserModel.findAll().then(data => {
          const users = utils.queryResultToJson(data)

          if (users.data?.length) {
            for (let i = 0; i < users.data.length; i++) {
              solved =
                                solved &&
                                utils.containsOrEscaped(dataString, users.data[i].email) &&
                                utils.contains(dataString, users.data[i].password)

              if (!solved) break
            }

            if (solved) {
              challengeUtils.solve(challenges.unionSqlInjectionChallenge)
            }
          }
        }).catch((error: Error) => { next(error) })
      }

      if (challengeUtils.notSolved(challenges.dbSchemaChallenge)) {
        let solved = true

        void models.sequelize
          .query('SELECT sql FROM sqlite_master')
          .then(([data]: any) => {
            const tableDefinitions = utils.queryResultToJson(data)

            if (tableDefinitions.data?.length) {
              for (let i = 0; i < tableDefinitions.data.length; i++) {
                if (tableDefinitions.data[i].sql) {
                  solved =
                                        solved &&
                                        utils.containsOrEscaped(
                                          dataString,
                                          tableDefinitions.data[i].sql
                                        )

                  if (!solved) break
                }
              }

              if (solved) {
                challengeUtils.solve(challenges.dbSchemaChallenge)
              }
            }
          })
      }
      // ------------------------------------------------------

      // localization step
      for (const p of products) {
        p.name = req.__(p.name)
        p.description = req.__(p.description)
      }

      res.json(utils.queryResultToJson(products))
    })
      .catch((error: ErrorWithParent) => { next(error.parent) })
  }
}
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge
