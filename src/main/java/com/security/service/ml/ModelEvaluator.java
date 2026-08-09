package com.security.service.ml;

import com.security.config.AppConfig;
import com.security.dao.AuditLogDAO;
import com.security.model.AuditLog;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.core.Instances;

import java.util.Random;

/**
 * ModelEvaluator - Measures ML model accuracy.
 * Uses 10-fold cross-validation (industry standard).
 * Reports: Accuracy, Precision, Recall, F1, Confusion Matrix.
 */
public class ModelEvaluator {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "ModelEvaluator";

    private final AppConfig    config       = AppConfig.getInstance();
    private final AuditLogDAO  auditLogDAO  = new AuditLogDAO();

    // ── Evaluate Any Classifier ───────────────────

    /**
     * Runs 10-fold cross-validation on the given classifier.
     * Prints and returns the Evaluation result.
     *
     * @param classifier  trained Weka classifier
     * @param data        training dataset
     * @param modelName   display name (e.g. "J48", "RandomForest")
     */
    public Evaluation evaluate(Classifier classifier,
                               Instances data,
                               String modelName) {
        int folds = config.getCrossValidationFolds();
        log.info(SOURCE, "Evaluating " + modelName
                + " with " + folds + "-fold cross-validation...");

        try {
            Evaluation eval = new Evaluation(data);
            eval.crossValidateModel(
                    classifier, data, folds, new Random(42));

            printResults(eval, modelName);
            saveEvaluationAudit(modelName, eval);
            return eval;

        } catch (Exception e) {
            log.error(SOURCE, "Evaluation failed for "
                    + modelName + ": " + e.getMessage());
            return null;
        }
    }

    // ── Print Results ────────────────────────────

    /** Prints a clean evaluation report to console. */
    private void printResults(Evaluation eval, String modelName) {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("  ML EVALUATION REPORT: " + modelName);
        System.out.println("=".repeat(50));

        System.out.printf("  Accuracy          : %.2f%%%n",
                eval.pctCorrect());
        System.out.printf("  Incorrectly Classd: %.2f%%%n",
                eval.pctIncorrect());
        System.out.printf("  Kappa Statistic   : %.4f%n",
                eval.kappa());

        System.out.println("\n  Per-Class Metrics:");
        System.out.println("  " + "-".repeat(46));
        System.out.printf("  %-10s %-12s %-10s %-10s%n",
                "Class", "Precision", "Recall", "F1-Score");
        System.out.println("  " + "-".repeat(46));

        String[] labels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
        for (int i = 0; i < labels.length; i++) {
            try {
                System.out.printf("  %-10s %-12.4f %-10.4f %-10.4f%n",
                        labels[i],
                        eval.precision(i),
                        eval.recall(i),
                        eval.fMeasure(i));
            } catch (Exception e) {
                System.out.printf("  %-10s N/A%n", labels[i]);
            }
        }

        System.out.println("\n  Confusion Matrix:");
        System.out.println("  (rows=actual, cols=predicted)");
        System.out.println("  " + "-".repeat(46));
        double[][] matrix = eval.confusionMatrix();
        String[] shortLabels = {"LOW ", "MED ", "HIGH", "CRIT"};
        for (int i = 0; i < matrix.length; i++) {
            System.out.print("  " + shortLabels[i] + " | ");
            for (double val : matrix[i]) {
                System.out.printf("%6.0f", val);
            }
            System.out.println();
        }
        System.out.println("=".repeat(50) + "\n");
    }

    // ── Save to Audit Log ────────────────────────

    /** Records the evaluation result in the audit log table. */
    private void saveEvaluationAudit(String modelName,
                                     Evaluation eval) {
        try {
            AuditLog entry = new AuditLog(
                    0,
                    DateHelper.now(),
                    "SYSTEM",
                    AuditLog.Action.MODEL_TRAINED,
                    modelName,
                    String.format("Accuracy=%.2f%%, Kappa=%.4f",
                            eval.pctCorrect(), eval.kappa()),
                    "INFO"
            );
            auditLogDAO.insert(entry);
        } catch (Exception e) {
            log.warn(SOURCE,
                    "Could not save evaluation audit: "
                            + e.getMessage());
        }
    }

    // ── Quick Accuracy Check ─────────────────────

    /**
     * Returns just the accuracy percentage.
     * Useful for quick comparisons between models.
     */
    public double getAccuracy(Classifier classifier,
                              Instances data) {
        try {
            Evaluation eval = new Evaluation(data);
            eval.crossValidateModel(
                    classifier, data,
                    config.getCrossValidationFolds(),
                    new Random(42));
            return eval.pctCorrect();
        } catch (Exception e) {
            log.error(SOURCE,
                    "getAccuracy failed: " + e.getMessage());
            return 0.0;
        }
    }
}