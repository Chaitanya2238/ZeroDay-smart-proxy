# Cybersecurity Threat Detection Dashboard

A React + Vite dashboard prototype for simulated cybersecurity threat detection, packet analysis, and vulnerability monitoring.

## Tech Stack

- React 18
- TypeScript with `.tsx` components
- Vite 6
- Tailwind CSS 4
- Radix UI / shadcn-style primitives
- Recharts for dashboard visualizations
- Motion for transitions and micro-interactions

## Features

- Search and file-upload entry flow for packet analysis input
- Simulated scanning screen with progress and live log playback
- Results dashboard with threat summary cards, charts, and a filterable findings table
- Shared threat data/config helpers to keep UI components smaller and easier to maintain

## Getting Started

### Prerequisites

- Node.js 20+ recommended
- npm 10+ or a compatible package manager

### Install

```bash
npm install
```

### Run the development server

```bash
npm run dev
```

### Build for production

```bash
npm run build
```

### Preview the production build

```bash
npm run preview
```

## Project Structure

```text
src/
  app/
    components/   Reusable screens and dashboard UI pieces
    lib/          Shared types, mock data, and helper functions
  styles/         Fonts, theme tokens, and Tailwind entrypoints
```

## Notes

This project originated from a Figma Make export and has been cleaned up into a more maintainable React structure with shared domain helpers and reusable UI wrappers.
