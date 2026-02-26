import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, info) {
    console.error("[React Error Boundary]", error, info?.componentStack);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          background: "#0f1114", color: "#e0ddd8", height: "100vh",
          display: "flex", flexDirection: "column", alignItems: "center",
          justifyContent: "center", fontFamily: "-apple-system, sans-serif", padding: 40,
        }}>
          <h1 style={{ color: "#E85D2A", marginBottom: 16, fontSize: 22 }}>Something went wrong</h1>
          <p style={{ color: "#9a9590", marginBottom: 24, maxWidth: 600, textAlign: "center", lineHeight: 1.6 }}>
            An unexpected error occurred in the UI. Your data is safe in the database.
            Click the button below to attempt recovery, or restart the application.
          </p>
          <pre style={{
            background: "#181b20", border: "1px solid #2a2d33", borderRadius: 8,
            padding: 16, maxWidth: 700, overflow: "auto", fontSize: 12, color: "#f85149",
            marginBottom: 24, whiteSpace: "pre-wrap", wordBreak: "break-word",
          }}>
            {this.state.error?.message || "Unknown error"}
          </pre>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              background: "#E85D2A", color: "#fff", border: "none",
              borderRadius: 6, padding: "10px 24px", cursor: "pointer", fontSize: 14,
              fontWeight: 600,
            }}
          >
            Try to Recover
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
