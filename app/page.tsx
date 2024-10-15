import SnykVulnerabilityChecker from '@/components/SnykVulnerabilityChecker';

export default function Home() {
  return (
    <main className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">Snyk Vulnerability Checker</h1>
      <SnykVulnerabilityChecker />
    </main>
  );
}