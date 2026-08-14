# Metrics budget pressure

This warning means a target is approaching its 1,000-runner or 5,600-control-
plane sample limit. The current reviewed classic maxima are 939 runner and
5,344 control-plane series. With native and classic histograms ingested
together, the reviewed Prometheus maxima are 969 runner and 5,494
control-plane samples per scrape, before Prometheus-generated target metadata.

1. Compare `scrape_samples_post_metric_relabeling` and response size before and
   after the most recent deployment.
2. Group series by `__name__` to find the growing family. For a histogram,
   include every classic bucket plus `_sum` and `_count`, and one additional
   native histogram sample for each initialized label set.
3. Inspect the family label values. Any identifier, path, URL, image, error, or
   user-controlled value is a privacy defect and must be removed at the source.
4. Check whether a closed enum gained values or a new histogram combined too
   many dimensions.
5. Update the cardinality manifest and rule/dashboard dependencies only after
   the bounded schema is reviewed.

The runner warning starts above 980 post-relabel samples, leaving a small but
intentional margin below the 1,000 hard limit; the control-plane warning starts
above 5,040. If a scrape exceeds its hard `sample_limit`, Prometheus rejects the
entire scrape. Do not increase either limit until both application cardinality
and native bucket/storage cost have been reviewed.

Do not solve application-label growth with metric relabeling alone: the process
has already allocated and encoded those series.
