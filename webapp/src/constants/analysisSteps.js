// Analysis pipeline steps configuration
export const ANALYSIS_STEPS = [
    {
        title: 'Evidence Ingestion',
        description: 'Parsing network flows and reassembling sessions from PCAP evidence',
        details: '> Extracting TCP/UDP streams...'
    },
    {
        title: 'Time-Window Correlation',
        description: 'Applying sliding window correlation heuristics across flow segments',
        details: '> Computing temporal overlap matrices...'
    },
    {
        title: 'Feature Extraction',
        description: 'Extracting deep traffic features (IAT/Packet Size distributions)',
        details: '> Building feature vectors...'
    },
    {
        title: 'Siamese Correlation Engine',
        description: 'Running neural network correlation on ingress/egress flow pairs',
        details: '> Inference on MPS accelerator...'
    },
    {
        title: 'Forensic Aggregation',
        description: 'Compiling findings and generating confidence metrics',
        details: '> Aggregating match scores...'
    }
];
