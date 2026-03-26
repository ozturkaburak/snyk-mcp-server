export type Scope = "FE" | "BE" | "UNKNOWN";

export interface NormalizedIssue {
  project: string;
  projectFullName: string;
  projectId: string;
  title: string;
  severity: string;
  dependency: string;
  version?: string;
  fixedIn?: string | null;
  vulnId: string;
  cve: string[];
  manifest: string;
  scope: Scope;
  snykUrl?: string;
}