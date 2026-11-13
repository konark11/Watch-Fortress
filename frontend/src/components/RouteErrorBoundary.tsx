import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  routeName: string;
}

interface State {
  error: Error | null;
}

export default class RouteErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error(`Failed to render ${this.props.routeName}:`, error, errorInfo);
  }

  render() {
    if (this.state.error) {
      return (
        <div role="alert" className="border border-[var(--critical)] rounded p-4 text-sm text-[var(--critical)]">
          <h1 className="font-semibold">Unable to render this page.</h1>
          <p className="mt-1 text-xs text-[var(--text-secondary)]">
            Refresh the page or return to another section of Watch Fortress.
          </p>
        </div>
      );
    }
    return this.props.children;
  }
}
