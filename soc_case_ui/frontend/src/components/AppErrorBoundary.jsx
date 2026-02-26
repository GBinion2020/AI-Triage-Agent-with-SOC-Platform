import React from 'react';

export default class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      message: error?.message ? String(error.message) : 'Unexpected render error.',
    };
  }

  componentDidCatch(_error, _info) {
    // Keep silent in UI; fallback panel is enough for operators.
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="card panel" style={{ margin: 18, padding: 16 }}>
          <h2>Case UI Render Error</h2>
          <p style={{ marginTop: 8 }}>
            {this.state.message || 'Unexpected render error.'}
          </p>
          <p style={{ marginTop: 8, color: '#9bb0d2' }}>
            Refresh the page. If this persists, the payload for this case contains an unexpected shape.
          </p>
        </div>
      );
    }
    return this.props.children;
  }
}
