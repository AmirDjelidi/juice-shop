import { QueryTypes } from 'sequelize'
import {NextFunction} from "express";

export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {

    console.log("here")

    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = criteria.toString().substring(0, 200)

    // only allow apple OR orange searches ← fixed logic
    if (
      !criteria.startsWith("apple") &&
      !criteria.startsWith("orange")
    ) {
      res.status(400).send()
      return
    }

    // ---- SAFE: parameterized query ----
    models.sequelize.query(
      `SELECT * FROM Products
       WHERE (
               (name LIKE :search OR description LIKE :search)
                 AND deletedAt IS NULL
               )
       ORDER BY name`,
      {
        replacements: { search: `%${criteria}%` },
        type: QueryTypes.SELECT
      }
    )
      .then((products: any[]) => {

        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }

        res.json(utils.queryResultToJson(products))
      })
      .catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}
