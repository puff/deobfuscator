package com.javadeobfuscator.deobfuscator.transformers.special;

import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.executor.Context;
import com.javadeobfuscator.deobfuscator.executor.defined.JVMMethodProvider;
import com.javadeobfuscator.deobfuscator.executor.defined.MappedFieldProvider;
import com.javadeobfuscator.deobfuscator.executor.defined.MappedMethodProvider;
import com.javadeobfuscator.deobfuscator.executor.providers.ComparisonProvider;
import com.javadeobfuscator.deobfuscator.executor.providers.DelegatingProvider;
import com.javadeobfuscator.deobfuscator.executor.values.JavaValue;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.util.Printer;
import org.objectweb.asm.util.Textifier;
import org.objectweb.asm.util.TraceMethodVisitor;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Base64;

public class SkytilsTransformer extends Transformer<TransformerConfig> {
    @Override
    public boolean transform() throws Throwable {
        System.out.println("[Skytils] [StringEncryptionTransformer] Starting TweakerUtil.undoString ");

        DelegatingProvider provider = new DelegatingProvider();
        provider.register(new MappedFieldProvider());
        provider.register(new JVMMethodProvider());
        provider.register(new MappedMethodProvider(classes));

        provider.register(new ComparisonProvider() {
            @Override
            public boolean instanceOf(JavaValue target, Type type, Context context) {
                return false;
            }

            @Override
            public boolean checkcast(JavaValue target, Type type, Context context) {
                return true;
            }

            @Override
            public boolean checkEquality(JavaValue first, JavaValue second, Context context) {
                return false;
            }

            @Override
            public boolean canCheckInstanceOf(JavaValue target, Type type, Context context) {
                return false;
            }

            @Override
            public boolean canCheckcast(JavaValue target, Type type, Context context) {
                return true;
            }

            @Override
            public boolean canCheckEquality(JavaValue first, JavaValue second, Context context) {
                return false;
            }
        });

        Context context = new Context(provider);
        context.dictionary = classpath;
        context.constantPools = getDeobfuscator().getConstantPools();
        context.file = getDeobfuscator().getConfig().getInput();

        int decryptedCount = 0;
        for (ClassNode classNode : classNodes()) {
            for (final MethodNode methodNode : classNode.methods) {
                if (methodNode.instructions == null)
                    continue;

                for (final AbstractInsnNode instruction : methodNode.instructions.toArray()) {
                    if (instruction instanceof MethodInsnNode && instruction.getOpcode() == INVOKESTATIC) {
                        MethodInsnNode methodInsnNode = (MethodInsnNode) instruction;
                        if (methodInsnNode.owner.equals("gg/skytils/skytilsmod/loader/TweakerUtil")) {
                            if (methodInsnNode.name.equals("undoString")) {
                                if (methodInsnNode.getPrevious().getOpcode() == LDC) {
                                    LdcInsnNode encryptedString = (LdcInsnNode) methodInsnNode.getPrevious();
                                    String decryptedString = decrypt((String) encryptedString.cst);
                                    methodNode.instructions.insert(methodInsnNode, new LdcInsnNode(decryptedString));
                                    methodNode.instructions.remove(methodInsnNode);
                                    methodNode.instructions.remove(encryptedString);
                                    decryptedCount++;
                                } else {
                                    System.out.println(prettyprint(methodInsnNode.getPrevious()));
                                }
                            } else if (methodInsnNode.name.equals("transformInPlace2")) {

                            }
                        }
                    }
                }
            }

            System.out.println("[Skytils] [StringEncryptionTransformer] Decrypted " + decryptedCount + " strings.");

            return true;
        }

        return false;
    }

    String decrypt(String string) {
        return new String(Base64.getDecoder().decode(string.chars().map(n -> n - 1).collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString()));
    }

    private static final Printer printer = new Textifier();
    private static final TraceMethodVisitor methodPrinter = new TraceMethodVisitor(printer);

    public static String prettyprint(AbstractInsnNode insnNode) {
        insnNode.accept(methodPrinter);
        StringWriter sw = new StringWriter();
        printer.print(new PrintWriter(sw));
        printer.getText().clear();
        return sw.toString();
    }
}
