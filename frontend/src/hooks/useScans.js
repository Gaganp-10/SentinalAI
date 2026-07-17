import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { triggerScan, getScanStatus, getProjectScans } from '../api/scans';

export const useScans = (projectId) => {
  const queryClient = useQueryClient();

  const scansQuery = useQuery({
    queryKey: ['scans', projectId],
    queryFn: () => getProjectScans(projectId),
    enabled: !!projectId,
  });

  const triggerScanMutation = useMutation({
    mutationFn: () => triggerScan(projectId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['scans', projectId] });
    },
  });

  return {
    scans: scansQuery.data || [],
    isLoading: scansQuery.isLoading,
    error: scansQuery.error,
    refetch: scansQuery.refetch,
    triggerScan: triggerScanMutation.mutateAsync,
    isTriggering: triggerScanMutation.isPending,
  };
};

export const useScanStatus = (scanId) => {
  const queryClient = useQueryClient();

  const scanQuery = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScanStatus(scanId),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (data && (data.status === 'pending' || data.status === 'running')) {
        return 2000; // poll every 2 seconds if running
      }
      return false; // stop polling once completed/failed
    },
  });

  return {
    scan: scanQuery.data,
    isLoading: scanQuery.isLoading,
    error: scanQuery.error,
    refetch: scanQuery.refetch,
  };
};
