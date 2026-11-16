/** INTENTIONALLY VULNERABLE TEST FIXTURE */
import { markup } from "@odoo/owl";
export function render(el, data) {
    el.innerHTML = data.comment;                 // CG-JS-XSS-001
    const html = markup(data.description);       // CG-JS-XSS-002
    localStorage.setItem("auth_token", data.token); // CG-JS-STORAGE-001
    return eval(data.formula);                   // CG-JS-EVAL-001
}
