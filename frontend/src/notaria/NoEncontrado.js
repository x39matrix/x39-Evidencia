import React from 'react';
import { Link } from 'react-router-dom';

export default function NoEncontrado() {
  return (
    <main className="nt-wrap" style={{ padding: '40px 20px 80px' }} data-testid="not-found-page">
      <h1>404 — Página no encontrada / Page not found</h1>
      <p lang="es">Este recurso no existe en x39matrix.org. Comprueba la dirección.</p>
      <p lang="en">This resource does not exist on x39matrix.org. Check the address.</p>
      <Link to="/">Volver al inicio / Back to home</Link>
    </main>
  );
}
