import { Component } from "react";

// A tab that throws while drawing never blanks the page: it is replaced by a short message with a retry. The page keys it by vertical, mode, person and tab,
// so switching any of them starts from a clean slate.
export default class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { failed: false }; }
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (this.state.failed) return <p className="app-error" role="alert" data-testid="boundary">This tab could not be drawn. <button type="button" className="primary" onClick={() => this.setState({ failed: false })}>Try again</button></p>;
    return this.props.children;
  }
}
