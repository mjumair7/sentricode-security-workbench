// Intentionally vulnerable static fixture. Never run or deploy this file.
export function renderReceipt(user: { password: string }, receipt: string) {
  console.log(user.password);
  document.body.innerHTML = receipt;
  return eval(receipt);
}
