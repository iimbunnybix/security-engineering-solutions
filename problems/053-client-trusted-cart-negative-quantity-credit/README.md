# 053 · Shoppers checked out with negative totals and the difference was credited to their wallets

## Problem
An electronics web shop lets customers pay from a store wallet and credits
the wallet automatically when an order total comes out below zero (that
path existed for price-match adjustments). Finance noticed wallet balances
growing with no matching refunds. The orders behind them looked absurd:
one `cable` at 9.99 plus `headphones` with quantity **-2**, total **-388.01**,
so the shopper got the cable and 388.01 of wallet credit. Other orders
bought headphones listed at 199.00 for **0.01**, or for 1.99 using a
quantity of `0.01`. Every order went through the normal checkout API; the
attackers had only edited the JSON in their browser's developer tools.

## Root cause
The checkout endpoint trusted the cart exactly as the browser sent it:

```python
total += float(line["unit_price"]) * float(line["quantity"])
```

- **Price came from the client.** The cart page sent each line's
  `unit_price`, and the server used it instead of looking it up.
- **Quantity was never validated.** The `<input type="number" min="1">` in
  the page was the only check, and it does not run when someone sends the
  request directly. Negative, zero and fractional quantities were all
  multiplied in.
- **Nothing refused a negative total**, and the wallet-credit path turned
  it straight into money.

`ReproduceProblem` reproduces all three orders (-388.01, 0.01 and 1.99).

## Solution
`checkout_total` treats the cart as a list of *requests* (SKU + quantity)
and prices it entirely on the server:
- **Prices come from the catalog.** Any `unit_price` field is ignored.
  Unknown SKUs are rejected.
- **Quantities must be real integers from 1 to 20.** `bool` is rejected
  explicitly because `True == 1` in Python; floats and strings are
  rejected rather than converted.
- **Repeated SKUs are merged** before the limit is checked, so twenty
  lines of one item cannot bypass the per-item limit.
- **Money is `Decimal`**, quantised to cents, so no float rounding.
- **A negative total is refused** even if a future discount rule or a bad
  catalog row produces one: checkout must never pay out.

## Trade-offs
- The client can no longer show a price the server will not honour, so the
  cart page must re-fetch prices, and a price change between page load and
  checkout should be shown to the user rather than silently applied.
- The quantity cap of 20 is a business rule; bulk buyers need a separate
  flow (or a per-SKU limit table) instead of a higher global cap.
- Discounts and coupons must also be computed server-side from codes, never
  accepted as amounts; that logic is outside this example.
- Validating with a schema library (e.g. pydantic or JSON Schema) is a good
  alternative for the type checks, but the price lookup and the
  non-negative-total rule are business logic and still belong here.

## Run
```bash
python -m unittest -v test_solution.py
```
