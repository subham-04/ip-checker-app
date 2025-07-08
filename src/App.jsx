import React, { useState, useEffect } from 'react';
import {
  ThemeProvider,
  createTheme,
  CssBaseline,
  Container,
  TextField,
  Button,
  Typography,
  TableContainer,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  Paper,
  Box,
  CircularProgress,
  Snackbar,
  Alert,
  FormControlLabel,
  Checkbox,
  Tab,
  Tabs,
  IconButton,
} from '@mui/material';
import { styled } from '@mui/material/styles';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import KeyboardArrowUpIcon from '@mui/icons-material/KeyboardArrowUp';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import { FaLinkedin } from 'react-icons/fa'; // Import FaLinkedin icon

// Define a dark theme for Material UI with the new color scheme
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#49bb78', // --color-primary
      light: 'rgba(73, 187, 120, 0.4)', // --color-primary-variant (used as a lighter shade)
    },
    secondary: {
      main: '#f48fb1', // Keeping a distinct secondary for buttons if needed
    },
    background: {
      default: '#000', // --color-bg
      paper: '#242424',   // --color-bg-variant
    },
    text: {
      primary: '#fff', // --color-white
      secondary: 'hsla(0, 0%, 100%, .6)', // --color-light
    },
    // Custom accent color for specific use cases like the LinkedIn hover
    accent: {
      main: '#b6d9f5', // --text-accent
    },
  },
  typography: {
    fontFamily: '"Inter", sans-serif', // Default font remains Inter
    h4: {
      fontFamily: '"Merriweather Sans", "Inter", sans-serif', // Specifically target h4 for a classy look
      fontWeight: 600, // Make it a bit bolder for emphasis
    },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 12,
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius: 8,
          },
        },
      },
    },
  },
});

// Styled components for better layout and spacing
const StyledContainer = styled(Container)(({ theme }) => ({
  marginTop: theme.spacing(4),
  marginBottom: theme.spacing(4),
  display: 'flex',
  flexDirection: 'column',
  gap: theme.spacing(3),
}));

const InputSection = styled(Box)(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
  gap: theme.spacing(2),
  padding: theme.spacing(3),
  backgroundColor: theme.palette.background.paper,
  borderRadius: theme.shape.borderRadius,
  boxShadow: theme.shadows[3],
}));

const ButtonGroup = styled(Box)(({ theme }) => ({
  display: 'flex',
  gap: theme.spacing(2),
  justifyContent: 'flex-end',
  marginTop: theme.spacing(2),
  marginBottom: theme.spacing(2),
}));

const ResultsSection = styled(Box)(({ theme }) => ({
  padding: theme.spacing(3),
  backgroundColor: theme.palette.background.paper,
  borderRadius: theme.shape.borderRadius,
  boxShadow: theme.shadows[3],
}));

// --- Validation Functions ---
const isValidIp = (ip) => {
  // Regex for IPv4 and basic IPv6 (more robust IPv6 regex is very long)
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1}[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){2}[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){3}[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){4}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){6}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$/i; // Simplified IPv6 regex for common patterns
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

const isValidDomain = (domain) => {
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
  return domainRegex.test(domain);
};

const isValidFileHash = (hash) => {
  // MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)
  const hashRegex = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
  return hashRegex.test(hash);
};

const isValidUrl = (url) => {
  // Basic URL regex, covers http, https, and common TLDs
  const urlRegex = /^(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/[a-zA-Z0-9]+\.[^\s]{2,}|[a-zA-Z0-9]+\.[^\s]{2,})$/i;
  return urlRegex.test(url);
};


// --- IP Checker Component ---
function IPChecker({ api_key, showSnackbar, loading, setLoading, results, setResults }) {
  const [ip_addresses, setIpAddresses] = useState('');

  const BACKEND_URL = 'http://localhost:5000/check_ips';

  const checkIPs = async () => {
    if (!api_key) {
      showSnackbar('Please enter your VirusTotal API Key.', 'error');
      return;
    }
    if (!ip_addresses) {
      showSnackbar('Please enter IP addresses to check.', 'error');
      return;
    }

    const ips = ip_addresses.split(',').map(ip => ip.trim()).filter(ip => ip);
    const invalidIps = ips.filter(ip => !isValidIp(ip));

    if (invalidIps.length > 0) {
      showSnackbar(`Invalid IP address format(s) found: ${invalidIps.join(', ')}. Please correct them.`, 'error');
      return;
    }

    setLoading(true);
    setResults([]);

    try {
      const response = await fetch(BACKEND_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          apiKey: api_key,
          ipAddresses: ips,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Backend error: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data);
      showSnackbar('IP check completed.', 'success');

    } catch (error) {
      console.error('Error calling backend for IPs:', error);
      showSnackbar(`Failed to check IPs: ${error.message}`, 'error');
      setResults(ips.map(ip => ({
        ip: ip,
        malicious: 'Error',
        harmless: 'Error',
        undetected: 'Error',
        lastAnalysisDate: 'Error',
        tags: 'Error',
        isp: 'Error',
      })));
    } finally {
      setLoading(false);
    }
  };

  const copyResults = () => {
    if (results.length === 0) {
      showSnackbar('No results to copy.', 'info');
      return;
    }
    const header = ['IP Address', 'Malicious Votes', 'Harmless Votes', 'Undetected', 'Last Analysis Date', 'ISP/ASN Owner', 'Tags'].join('\t');
    const rows = results.map(row =>
      [row.ip, row.malicious, row.harmless, row.undetected, row.lastAnalysisDate, row.isp, Array.isArray(row.tags) ? row.tags.join(', ') : row.tags].join('\t')
    ).join('\n');
    const textToCopy = `${header}\n${rows}`;
    try {
      const textarea = document.createElement('textarea');
      textarea.value = textToCopy;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showSnackbar('Results copied to clipboard!', 'success');
    } catch (err) {
      console.error('Failed to copy text: ', err);
      showSnackbar('Failed to copy results to clipboard.', 'error');
    }
  };

  const exportToCsv = () => {
    if (results.length === 0) {
      showSnackbar('No results to export.', 'info');
      return;
    }
    const header = ['IP Address', 'Malicious Votes', 'Harmless Votes', 'Undetected', 'Last Analysis Date', 'ISP/ASN Owner', 'Tags'].join(',');
    const rows = results.map(row =>
      `"${row.ip}","${row.malicious}","${row.harmless}","${row.undetected}","${row.lastAnalysisDate}","${row.isp}","${Array.isArray(row.tags) ? row.tags.join('; ') : row.tags}"`
    ).join('\n');
    const csvContent = `data:text/csv;charset=utf-8,${header}\n${rows}`;
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'ip_checker_results.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showSnackbar('Results exported to CSV!', 'success');
  };

  return (
    <InputSection>
      <TextField
        label="IP Addresses (comma-separated)"
        variant="outlined"
        fullWidth
        multiline
        rows={4}
        value={ip_addresses}
        onChange={(e) => setIpAddresses(e.target.value)}
        placeholder="e.g., 8.8.8.8, 1.1.1.1, 192.168.1.1"
        helperText="Enter multiple IP addresses separated by commas."
        inputProps={{ maxLength: 2000 }} // Limit input length
      />
      <Button
        variant="contained"
        color="primary"
        onClick={checkIPs}
        disabled={loading}
        sx={{ mt: 2, py: 1.5 }}
      >
        {loading ? <CircularProgress size={24} color="inherit" /> : 'Check IPs'}
      </Button>

      {results.length > 0 && (
        <ResultsSection>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h5" component="h2">
              Analysis Results
            </Typography>
            <ButtonGroup>
              <Button
                variant="outlined"
                color="secondary"
                onClick={copyResults}
              >
                Copy Results
              </Button>
              <Button
                variant="outlined"
                color="secondary"
                onClick={exportToCsv}
              >
                Export to CSV
              </Button>
            </ButtonGroup>
          </Box>
          <TableContainer component={Paper}>
            <Table sx={{ minWidth: 650 }} aria-label="IP analysis results table">
              <TableHead>
                <TableRow>
                  <TableCell>IP Address</TableCell>
                  <TableCell align="right">Malicious</TableCell>
                  <TableCell align="right">Harmless</TableCell>
                  <TableCell align="right">Undetected</TableCell>
                  <TableCell>Last Analysis Date</TableCell>
                  <TableCell>ISP/ASN Owner</TableCell>
                  <TableCell>Tags</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {results.map((row) => (
                  <TableRow
                    key={row.ip}
                    sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                  >
                    <TableCell component="th" scope="row">
                      {row.ip}
                    </TableCell>
                    <TableCell
                      align="right"
                      sx={{ color: row.malicious === 0 ? 'green' : (row.malicious > 0 ? 'red' : 'inherit') }}
                    >
                      {row.malicious}
                    </TableCell>
                    <TableCell align="right">{row.harmless}</TableCell>
                    <TableCell align="right">{row.undetected}</TableCell>
                    <TableCell>{row.lastAnalysisDate}</TableCell>
                    <TableCell>{row.isp}</TableCell>
                    <TableCell>{Array.isArray(row.tags) ? row.tags.join(', ') : row.tags}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </ResultsSection>
      )}
    </InputSection>
  );
}

// --- Domain Checker Component ---
function DomainChecker({ api_key, showSnackbar, loading, setLoading, results, setResults }) {
  const [domain_addresses, setDomainAddresses] = useState('');

  const BACKEND_URL = 'http://localhost:5000/check_domains';

  const checkDomains = async () => {
    if (!api_key) {
      showSnackbar('Please enter your VirusTotal API Key.', 'error');
      return;
    }
    if (!domain_addresses) {
      showSnackbar('Please enter domain names to check.', 'error');
      return;
    }

    const domains = domain_addresses.split(',').map(domain => domain.trim()).filter(domain => domain);
    const invalidDomains = domains.filter(domain => !isValidDomain(domain));

    if (invalidDomains.length > 0) {
      showSnackbar(`Invalid domain format(s) found: ${invalidDomains.join(', ')}. Please correct them.`, 'error');
      return;
    }

    setLoading(true);
    setResults([]);

    try {
      const response = await fetch(BACKEND_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          apiKey: api_key,
          domainAddresses: domains,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Backend error: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data);
      showSnackbar('Domain check completed.', 'success');

    } catch (error) {
      console.error('Error calling backend for Domains:', error);
      showSnackbar(`Failed to check Domains: ${error.message}`, 'error');
      setResults(domains.map(domain => ({
        domain: domain,
        malicious: 'Error',
        harmless: 'Error',
        undetected: 'Error',
        reputation: 'Error',
        lastAnalysisDate: 'Error',
        creationDate: 'Error',
        registrar: 'Error',
        tags: 'Error',
      })));
    } finally {
      setLoading(false);
    }
  };

  const copyResults = () => {
    if (results.length === 0) {
      showSnackbar('No results to copy.', 'info');
      return;
    }
    const header = ['Domain', 'Malicious Votes', 'Harmless Votes', 'Undetected', 'Reputation', 'Last Analysis Date', 'Creation Date', 'Registrar', 'Tags'].join('\t');
    const rows = results.map(row =>
      [row.domain, row.malicious, row.harmless, row.undetected, row.reputation, row.lastAnalysisDate, row.creationDate, row.registrar, Array.isArray(row.tags) ? row.tags.join(', ') : row.tags].join('\t')
    ).join('\n');
    const textToCopy = `${header}\n${rows}`;
    try {
      const textarea = document.createElement('textarea');
      textarea.value = textToCopy;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showSnackbar('Results copied to clipboard!', 'success');
    } catch (err) {
      console.error('Failed to copy text: ', err);
      showSnackbar('Failed to copy results to clipboard.', 'error');
    }
  };

  const exportToCsv = () => {
    if (results.length === 0) {
      showSnackbar('No results to export.', 'info');
      return;
    }
    const header = ['Domain', 'Malicious Votes', 'Harmless Votes', 'Undetected', 'Reputation', 'Last Analysis Date', 'Creation Date', 'Registrar', 'Tags'].join(',');
    const rows = results.map(row =>
      `"${row.domain}","${row.malicious}","${row.harmless}","${row.undetected}","${row.reputation}","${row.lastAnalysisDate}","${row.creationDate}","${row.registrar}","${Array.isArray(row.tags) ? row.tags.join('; ') : row.tags}"`
    ).join('\n');
    const csvContent = `data:text/csv;charset=utf-8,${header}\n${rows}`;
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'domain_checker_results.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showSnackbar('Results exported to CSV!', 'success');
  };

  return (
    <InputSection>
      <TextField
        label="Domain Names (comma-separated)"
        variant="outlined"
        fullWidth
        multiline
        rows={4}
        value={domain_addresses}
        onChange={(e) => setDomainAddresses(e.target.value)}
        placeholder="e.g., google.com, example.org, badsite.net"
        helperText="Enter multiple domain names separated by commas."
        inputProps={{ maxLength: 2000 }} // Limit input length
      />
      <Button
        variant="contained"
        color="primary"
        onClick={checkDomains}
        disabled={loading}
        sx={{ mt: 2, py: 1.5 }}
      >
        {loading ? <CircularProgress size={24} color="inherit" /> : 'Check Domains'}
      </Button>

      {results.length > 0 && (
        <ResultsSection>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h5" component="h2">
              Analysis Results
            </Typography>
            <ButtonGroup>
              <Button
                variant="outlined"
                color="secondary"
                onClick={copyResults}
              >
                Copy Results
              </Button>
              <Button
                variant="outlined"
                color="secondary"
                onClick={exportToCsv}
              >
                Export to CSV
              </Button>
            </ButtonGroup>
          </Box>
          <TableContainer component={Paper}>
            <Table sx={{ minWidth: 650 }} aria-label="Domain analysis results table">
              <TableHead>
                <TableRow>
                  <TableCell>Domain</TableCell>
                  <TableCell align="right">Malicious</TableCell>
                  <TableCell align="right">Harmless</TableCell>
                  <TableCell align="right">Undetected</TableCell>
                  <TableCell align="right">Reputation</TableCell>
                  <TableCell>Last Analysis Date</TableCell>
                  <TableCell>Creation Date</TableCell>
                  <TableCell>Registrar</TableCell>
                  <TableCell>Tags</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {results.map((row) => (
                  <TableRow
                    key={row.domain}
                    sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                  >
                    <TableCell component="th" scope="row">
                      {row.domain}
                    </TableCell>
                    <TableCell
                      align="right"
                      sx={{ color: row.malicious === 0 ? 'green' : (row.malicious > 0 ? 'red' : 'inherit') }}
                    >
                      {row.malicious}
                    </TableCell>
                    <TableCell align="right">{row.harmless}</TableCell>
                    <TableCell align="right">{row.undetected}</TableCell>
                    <TableCell align="right">{row.reputation}</TableCell>
                    <TableCell>{row.lastAnalysisDate}</TableCell>
                    <TableCell>{row.creationDate}</TableCell>
                    <TableCell>{row.registrar}</TableCell>
                    <TableCell>{Array.isArray(row.tags) ? row.tags.join(', ') : row.tags}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </ResultsSection>
      )}
    </InputSection>
  );
}

// --- File Hash Checker Component ---
function FileHashChecker({ api_key, showSnackbar, loading, setLoading, results, setResults }) {
  const [file_hashes, setFileHashes] = useState('');

  const BACKEND_URL = 'http://localhost:5000/check_file_hashes';

  const checkFileHashes = async () => {
    if (!api_key) {
      showSnackbar('Please enter your VirusTotal API Key.', 'error');
      return;
    }
    if (!file_hashes) {
      showSnackbar('Please enter file hashes to check.', 'error');
      return;
    }

    const hashes = file_hashes.split(',').map(hash => hash.trim()).filter(hash => hash);
    const invalidHashes = hashes.filter(hash => !isValidFileHash(hash));

    if (invalidHashes.length > 0) {
      showSnackbar(`Invalid file hash format(s) found: ${invalidHashes.join(', ')}. Please correct them.`, 'error');
      return;
    }

    setLoading(true);
    setResults([]);

    try {
      const response = await fetch(BACKEND_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          apiKey: api_key,
          fileHashes: hashes,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Backend error: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data);
      showSnackbar('File hash check completed.', 'success');

    } catch (error) {
      console.error('Error calling backend for File Hashes:', error);
      showSnackbar(`Failed to check File Hashes: ${error.message}`, 'error');
      setResults(hashes.map(hash => ({
        hash: hash,
        malicious: 'Error',
        harmless: 'Error',
        undetected: 'Error',
        lastAnalysisDate: 'Error',
        size: 'Error',
        type: 'Error',
        tags: 'Error',
      })));
    } finally {
      setLoading(false);
    }
  };

  const copyResults = () => {
    if (results.length === 0) {
      showSnackbar('No results to copy.', 'info');
      return;
    }
    const header = ['File Hash', 'Malicious Votes', 'Harmless Votes', 'Undetected', 'Last Analysis Date', 'Size', 'Type', 'Tags'].join('\t');
    const rows = results.map(row =>
      [row.hash, row.malicious, row.harmless, row.undetected, row.lastAnalysisDate, row.size, row.type, Array.isArray(row.tags) ? row.tags.join(', ') : row.tags].join('\t')
    ).join('\n');
    const textToCopy = `${header}\n${rows}`;
    try {
      const textarea = document.createElement('textarea');
      textarea.value = textToCopy;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showSnackbar('Results copied to clipboard!', 'success');
    } catch (err) {
      console.error('Failed to copy text: ', err);
      showSnackbar('Failed to copy results to clipboard.', 'error');
    }
  };

  const exportToCsv = () => {
    if (results.length === 0) {
      showSnackbar('No results to export.', 'info');
      return;
    }
    const header = ['File Hash', 'Malicious Votes', 'Harmless Votes', 'Undetected', 'Last Analysis Date', 'Size', 'Type', 'Tags'].join(',');
    const rows = results.map(row =>
      `"${row.hash}","${row.malicious}","${row.harmless}","${row.undetected}","${row.lastAnalysisDate}","${row.size}","${row.type}","${Array.isArray(row.tags) ? row.tags.join('; ') : row.tags}"`
    ).join('\n');
    const csvContent = `data:text/csv;charset=utf-8,${header}\n${rows}`;
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'file_hash_checker_results.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showSnackbar('Results exported to CSV!', 'success');
  };

  return (
    <InputSection>
      <TextField
        label="File Hashes (comma-separated)"
        variant="outlined"
        fullWidth
        multiline
        rows={4}
        value={file_hashes}
        onChange={(e) => setFileHashes(e.target.value)}
        placeholder="e.g., 275a021bbfb6489e54d471899f7db9d1663fc695ec2bd2a246e03494237ad266, ..."
        helperText="Enter multiple file hashes (MD5, SHA1, SHA256) separated by commas."
        inputProps={{ maxLength: 2000 }} // Limit input length
      />
      <Button
        variant="contained"
        color="primary"
        onClick={checkFileHashes}
        disabled={loading}
        sx={{ mt: 2, py: 1.5 }}
      >
        {loading ? <CircularProgress size={24} color="inherit" /> : 'Check File Hashes'}
      </Button>

      {results.length > 0 && (
        <ResultsSection>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h5" component="h2">
              Analysis Results
            </Typography>
            <ButtonGroup>
              <Button
                variant="outlined"
                color="secondary"
                onClick={copyResults}
              >
                Copy Results
              </Button>
              <Button
                variant="outlined"
                color="secondary"
                onClick={exportToCsv}
              >
                Export to CSV
              </Button>
            </ButtonGroup>
          </Box>
          <TableContainer component={Paper}>
            <Table sx={{ minWidth: 650 }} aria-label="File hash analysis results table">
              <TableHead>
                <TableRow>
                  <TableCell>File Hash</TableCell>
                  <TableCell align="right">Malicious</TableCell>
                  <TableCell align="right">Harmless</TableCell>
                  <TableCell align="right">Undetected</TableCell>
                  <TableCell>Last Analysis Date</TableCell>
                  <TableCell>Size</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Tags</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {results.map((row) => (
                  <TableRow
                    key={row.hash}
                    sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                  >
                    <TableCell component="th" scope="row">
                      {row.hash}
                    </TableCell>
                    <TableCell
                      align="right"
                      sx={{ color: row.malicious === 0 ? 'green' : (row.malicious > 0 ? 'red' : 'inherit') }}
                    >
                      {row.malicious}
                    </TableCell>
                    <TableCell align="right">{row.harmless}</TableCell>
                    <TableCell align="right">{row.undetected}</TableCell>
                    <TableCell>{row.lastAnalysisDate}</TableCell>
                    <TableCell>{row.size}</TableCell>
                    <TableCell>{row.type}</TableCell>
                    <TableCell>{Array.isArray(row.tags) ? row.tags.join(', ') : row.tags}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </ResultsSection>
      )}
    </InputSection>
  );
}

// --- URL Checker Component ---
function URLChecker({ api_key, showSnackbar, loading, setLoading, results, setResults }) {
  const [urls, setUrls] = useState('');

  const BACKEND_URL = 'http://localhost:5000/check_urls';

  const checkUrls = async () => {
    if (!api_key) {
      showSnackbar('Please enter your VirusTotal API Key.', 'error');
      return;
    }
    if (!urls) {
      showSnackbar('Please enter URLs to check.', 'error');
      return;
    }

    const urlList = urls.split(',').map(url => url.trim()).filter(url => url);
    const invalidUrls = urlList.filter(url => !isValidUrl(url));

    if (invalidUrls.length > 0) {
      showSnackbar(`Invalid URL format(s) found: ${invalidUrls.join(', ')}. Please correct them.`, 'error');
      return;
    }

    setLoading(true);
    setResults([]);

    try {
      const response = await fetch(BACKEND_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          apiKey: api_key,
          urls: urlList,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Backend error: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data);
      showSnackbar('URL check completed.', 'success');

    } catch (error) {
      console.error('Error calling backend for URLs:', error);
      showSnackbar(`Failed to check URLs: ${error.message}`, 'error');
      setResults(urlList.map(url => ({
        url: url,
        malicious: 'Error',
        harmless: 'Error',
        undetected: 'Error',
        lastAnalysisDate: 'Error',
        title: 'Error',
        tags: 'Error',
      })));
    } finally {
      setLoading(false);
    }
  };

  const copyResults = () => {
    if (results.length === 0) {
      showSnackbar('No results to copy.', 'info');
      return;
    }
    const header = ['URL', 'Malicious Votes', 'Harmless Votes', 'Undetected', 'Last Analysis Date', 'Title', 'Tags'].join('\t');
    const rows = results.map(row =>
      [row.url, row.malicious, row.harmless, row.undetected, row.lastAnalysisDate, row.title, Array.isArray(row.tags) ? row.tags.join(', ') : row.tags].join('\t')
    ).join('\n');
    const textToCopy = `${header}\n${rows}`;
    try {
      const textarea = document.createElement('textarea');
      textarea.value = textToCopy;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showSnackbar('Results copied to clipboard!', 'success');
    } catch (err) {
      console.error('Failed to copy text: ', err);
      showSnackbar('Failed to copy results to clipboard.', 'error');
    }
  };

  const exportToCsv = () => {
    if (results.length === 0) {
      showSnackbar('No results to export.', 'info');
      return;
    }
    const header = ['URL', 'Malicious Votes', 'Harmless Votes', 'Undetected', 'Last Analysis Date', 'Title', 'Tags'].join(',');
    const rows = results.map(row =>
      `"${row.url}","${row.malicious}","${row.harmless}","${row.undetected}","${row.lastAnalysisDate}","${row.title}","${Array.isArray(row.tags) ? row.tags.join('; ') : row.tags}"`
    ).join('\n');
    const csvContent = `data:text/csv;charset=utf-8,${header}\n${rows}`;
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'url_checker_results.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showSnackbar('Results exported to CSV!', 'success');
  };

  return (
    <InputSection>
      <TextField
        label="URLs (comma-separated)"
        variant="outlined"
        fullWidth
        multiline
        rows={4}
        value={urls}
        onChange={(e) => setUrls(e.target.value)}
        placeholder="e.g., https://example.com, http://malicious.link"
        helperText="Enter multiple URLs separated by commas. Note: Analysis might take a moment if the URL is new to VirusTotal."
        inputProps={{ maxLength: 2000 }} // Limit input length
      />
      <Button
        variant="contained"
        color="primary"
        onClick={checkUrls}
        disabled={loading}
        sx={{ mt: 2, py: 1.5 }}
      >
        {loading ? <CircularProgress size={24} color="inherit" /> : 'Check URLs'}
      </Button>

      {results.length > 0 && (
        <ResultsSection>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h5" component="h2">
              Analysis Results
            </Typography>
            <ButtonGroup>
              <Button
                variant="outlined"
                color="secondary"
                onClick={copyResults}
              >
                Copy Results
              </Button>
              <Button
                variant="outlined"
                color="secondary"
                onClick={exportToCsv}
              >
                Export to CSV
              </Button>
            </ButtonGroup>
          </Box>
          <TableContainer component={Paper}>
            <Table sx={{ minWidth: 650 }} aria-label="URL analysis results table">
              <TableHead>
                <TableRow>
                  <TableCell>URL</TableCell>
                  <TableCell align="right">Malicious</TableCell>
                  <TableCell align="right">Harmless</TableCell>
                  <TableCell align="right">Undetected</TableCell>
                  <TableCell>Last Analysis Date</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Tags</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {results.map((row) => (
                  <TableRow
                    key={row.url}
                    sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                  >
                    <TableCell component="th" scope="row">
                      {row.url}
                    </TableCell>
                    <TableCell
                      align="right"
                      sx={{ color: row.malicious === 0 ? 'green' : (row.malicious > 0 ? 'red' : 'inherit') }}
                    >
                      {row.malicious}
                    </TableCell>
                    <TableCell align="right">{row.harmless}</TableCell>
                    <TableCell align="right">{row.undetected}</TableCell>
                    <TableCell>{row.lastAnalysisDate}</TableCell>
                    <TableCell>{row.title}</TableCell>
                    <TableCell>{Array.isArray(row.tags) ? row.tags.join(', ') : row.tags}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </ResultsSection>
      )}
    </InputSection>
  );
}


// --- Main App Component ---
function App() {
  const [api_key, setApiKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState('success');
  const [rememberApiKey, setRememberApiKey] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [isApiKeySectionCollapsed, setIsApiKeySectionCollapsed] = useState(false);
  const [currentTab, setCurrentTab] = useState(0);
  const [ipResults, setIpResults] = useState([]);
  const [domainResults, setDomainResults] = useState([]);
  const [fileHashResults, setFileHashResults] = useState([]);
  const [urlResults, setUrlResults] = useState([]);

  // Effect to load API key from localStorage when component mounts
  useEffect(() => {
    const storedApiKey = localStorage.getItem('virustotalApiKey');
    if (storedApiKey) {
      setApiKey(storedApiKey);
      setRememberApiKey(true);
      setIsApiKeySectionCollapsed(true);
    }
  }, []);

  // Function to show snackbar messages
  const showSnackbar = (message, severity = 'success') => {
    setSnackbarMessage(message);
    setSnackbarSeverity(severity);
    setSnackbarOpen(true);
  };

  const handleSnackbarClose = (event, reason) => {
    if (reason === 'clickaway') {
      return;
    }
    setSnackbarOpen(false);
  };

  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
    // Clear results when switching tabs
    setIpResults([]);
    setDomainResults([]);
    setFileHashResults([]);
    setUrlResults([]);
  };

  // Save/remove API key based on checkbox state whenever api_key or rememberApiKey changes
  useEffect(() => {
    if (rememberApiKey && api_key) {
      localStorage.setItem('virustotalApiKey', api_key);
    } else if (!rememberApiKey) {
      localStorage.removeItem('virustotalApiKey');
    }
  }, [api_key, rememberApiKey]);


  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <StyledContainer maxWidth="md">
        <Typography variant="h4" component="h1" align="center" gutterBottom>
          VirusTotal IP/Domain/File Hash/URL Checker
        </Typography>

        <InputSection>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6" component="h2">
              VirusTotal API Key Configuration
            </Typography>
            <IconButton
              onClick={() => setIsApiKeySectionCollapsed(!isApiKeySectionCollapsed)}
              color="primary"
              aria-label={isApiKeySectionCollapsed ? 'Expand API Key section' : 'Collapse API Key section'}
            >
              {isApiKeySectionCollapsed ? <KeyboardArrowDownIcon /> : <KeyboardArrowUpIcon />}
            </IconButton>
          </Box>

          {!isApiKeySectionCollapsed && (
            <>
              <TextField
                label="VirusTotal API Key"
                variant="outlined"
                fullWidth
                type={showApiKey ? 'text' : 'password'}
                value={api_key}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="Enter your VirusTotal API key here"
                helperText="Your API key is stored locally in your browser session and not sent to any server."
                inputProps={{ maxLength: 100 }} // Limit API key length
              />
              <FormControlLabel
                control={
                  <Checkbox
                    checked={rememberApiKey}
                    onChange={(e) => setRememberApiKey(e.target.checked)}
                    name="rememberApiKey"
                    color="primary"
                    disabled={!api_key}
                  />
                }
                label="Remember API Key for future sessions"
              />
            </>
          )}
          {isApiKeySectionCollapsed && (
            <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
              API Key section is collapsed. Click the arrow to expand.
            </Typography>
          )}
        </InputSection>

        <Paper sx={{ width: '100%', boxShadow: darkTheme.shadows[3] }}>
          <Tabs
            value={currentTab}
            onChange={handleTabChange}
            indicatorColor="primary"
            textColor="primary"
            centered
            sx={{ borderBottom: 1, borderColor: 'divider' }}
          >
            <Tab label="Check IPs" />
            <Tab label="Check Domains" />
            <Tab label="Check File Hashes" />
            <Tab label="Check URLs" />
          </Tabs>
        </Paper>

        {currentTab === 0 && (
          <IPChecker
            api_key={api_key}
            showSnackbar={showSnackbar}
            loading={loading}
            setLoading={setLoading}
            results={ipResults}
            setResults={setIpResults}
          />
        )}
        {currentTab === 1 && (
          <DomainChecker
            api_key={api_key}
            showSnackbar={showSnackbar}
            loading={loading}
            setLoading={setLoading}
            results={domainResults}
            setResults={setDomainResults}
          />
        )}
        {currentTab === 2 && (
          <FileHashChecker
            api_key={api_key}
            showSnackbar={showSnackbar}
            loading={loading}
            setLoading={setLoading}
            results={fileHashResults}
            setResults={setFileHashResults}
          />
        )}
        {currentTab === 3 && (
          <URLChecker
            api_key={api_key}
            showSnackbar={showSnackbar}
            loading={loading}
            setLoading={setLoading}
            results={urlResults}
            setResults={setUrlResults}
          />
        )}

        <Snackbar open={snackbarOpen} autoHideDuration={6000} onClose={handleSnackbarClose}>
          <Alert onClose={handleSnackbarClose} severity={snackbarSeverity} sx={{ width: '100%' }}>
            {snackbarMessage}
          </Alert>
        </Snackbar>

        {/* Creator attribution */}
        <Box sx={{
          mt: 4,
          textAlign: 'center',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 1,
          color: 'text.secondary',
          fontSize: '0.875rem',
        }}>
          <Typography variant="body2" color="textSecondary">
            Created by Subham
          </Typography>
          <a
            href="https://www.linkedin.com/in/subham0422/"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Subham's LinkedIn Profile"
            style={{
              display: 'flex',
              alignItems: 'center',
              textDecoration: 'none',
              color: 'inherit',
              transition: 'transform 0.3s ease-in-out, color 0.3s ease-in-out',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'scale(1.1)';
              e.currentTarget.style.color = darkTheme.palette.accent.main; // Use the new accent color
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'scale(1)';
              e.currentTarget.style.color = 'inherit';
            }}
          >
            <FaLinkedin size={24} style={{ marginRight: '4px' }} />
            <Typography variant="body2" component="span">
              LinkedIn
            </Typography>
          </a>
        </Box>

      </StyledContainer>
    </ThemeProvider>
  );
}

export default App;
