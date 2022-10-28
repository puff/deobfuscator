package com.javadeobfuscator.deobfuscator.transformers.branchlock;

import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.executor.Context;
import com.javadeobfuscator.deobfuscator.executor.MethodExecutor;
import com.javadeobfuscator.deobfuscator.executor.defined.JVMMethodProvider;
import com.javadeobfuscator.deobfuscator.executor.defined.MappedFieldProvider;
import com.javadeobfuscator.deobfuscator.executor.defined.MappedMethodProvider;
import com.javadeobfuscator.deobfuscator.executor.providers.ComparisonProvider;
import com.javadeobfuscator.deobfuscator.executor.providers.DelegatingProvider;
import com.javadeobfuscator.deobfuscator.executor.values.JavaValue;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.util.Printer;
import org.objectweb.asm.util.Textifier;
import org.objectweb.asm.util.TraceMethodVisitor;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

public class StringEncryptionTransformer extends Transformer<TransformerConfig> {

    @Override
    public boolean transform() throws Throwable {
        System.out.println("[Branchlock] [StringEncryptionTransformer] Starting");

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
            FieldInsnNode branchlockStringPool = getBranchlockStringPool(classNode);
            if (branchlockStringPool == null) {
               // System.out.println("[Branchlock] [StringEncryptionTransformer] Failed to find string pool for class " + classNode.name);
                continue;
            }

            for (final MethodNode methodNode : classNode.methods) {
                if (methodNode.instructions == null || methodNode.name.equals("<clinit>"))
                    continue;

                boolean gotStrings = false;
                for (final AbstractInsnNode instruction : methodNode.instructions.toArray()) {
                    if (instruction instanceof FieldInsnNode && instruction.getOpcode() == GETSTATIC) {
                        final FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;
                        if (Objects.equals(branchlockStringPool.name, fieldInstruction.name) && Objects.equals(branchlockStringPool.owner, fieldInstruction.owner))
                        {
                            MethodNode clinitMethod = classes.get(branchlockStringPool.owner).methods.stream().filter(mn -> mn.name.equals("<clinit>")).findFirst().orElse(null);
                            if (!gotStrings && clinitMethod != null) {
                                InsnList clinitInsnList = copy(clinitMethod.instructions);
//                                for (AbstractInsnNode insn : clinitMethod.instructions) {
//                                    if (insn instanceof MethodInsnNode) {
//                                        MethodInsnNode methodInsnNode = ((MethodInsnNode)insn);
//                                        //System.out.println(methodInsnNode.name + " " + methodInsnNode.owner);
//
//                                       // too lazy
//                                        //if (Objects.equals(methodInsnNode.owner, branchlockStringPool.owner) && !Objects.equals(methodInsnNode.name, branchlockStringPool.name))
//                                        //if (classNode.methods.stream().anyMatch(methodNode1 -> methodNode1.name.equals(methodInsnNode.name)))
//                                        if ((!methodInsnNode.owner.equals("java/lang/String") && !methodInsnNode.owner.equals("java/lang/StackTraceElement") && !methodInsnNode.owner.equals("java/lang/Throwable") && !methodInsnNode.owner.equals("java/lang/Integer")))
//                                        {
//                                            //clinitMethod.instructions.insert(insn, new InsnNode(NOP));
//                                            clinitMethod.instructions.remove(insn);
//                                        }
//                                    }
//                                     if (insn instanceof FieldInsnNode) {
//                                        FieldInsnNode fieldInsnNode = (FieldInsnNode)insn;
//
//                                        if (fieldInsnNode.getOpcode() == PUTSTATIC && !Objects.equals(fieldInsnNode.name, branchlockStringPool.name))
//                                        {
//                                            //System.out.println(fieldInsnNode.name + " | " + branchlockStringPool.name);
//                                            //clinitMethod.instructions.insert(insn, new InsnNode(NOP));
//                                            clinitMethod.instructions.remove(insn);
//                                        }
//                                    }
//
////                                    if (insn instanceof FieldInsnNode && insn.getOpcode() == Opcodes.PUTSTATIC) {
////                                        FieldInsnNode fieldInsnNode = ((FieldInsnNode)insn);
////                                        System.out.println(fieldInsnNode.name + " " + branchlockStringPool.name + " " + fieldInsnNode.owner + " " + branchlockStringPool.owner);
////                                        if (!Objects.equals(fieldInsnNode.name, branchlockStringPool.name) && Objects.equals(fieldInsnNode.owner, branchlockStringPool.owner))
////                                            clinitMethod.instructions.remove(insn);
////                                    }
//                                }

//                                if (classNode.name.contains("FailSafe/Discord")) {
//                                    for (AbstractInsnNode insn : clinitInsnList)
//                                        System.out.println(prettyprint(insn));
//
//                                    System.out.println("-----------------");
//                                }

                                ListIterator<AbstractInsnNode> li = clinitMethod.instructions.iterator(clinitMethod.instructions.size());
                                AbstractInsnNode mi = null;
                                boolean f = false;
                                int startIndex = 0;
                                while (li.hasPrevious()) {
                                    mi = li.previous();
                                    if (mi.getOpcode() == GOTO) {
                                        if (!f) {
                                            f = true;
                                            continue;
                                        }
                                        //System.out.println(clinitInsnList.indexOf(mi) + " | " + clinitInsnList.size());
                                        startIndex = clinitMethod.instructions.indexOf(mi) + 1;
                                        //int endIndex = clinitMethod.instructions.size() - 5; // don't delete beyond the return statement

                                        break;
                                    }
                                }

                                ListIterator<AbstractInsnNode> li2 = clinitMethod.instructions.iterator(startIndex);
                                AbstractInsnNode mi2 = null;
                                while (li2.hasNext()) {
//                                            System.out.println(li2.nextIndex() + " | " + endIndex);
//                                            if (li2.nextIndex() == endIndex)
//                                                break;

                                    mi2 = li2.next();
                                    if (mi2 instanceof LabelNode)
                                        continue;

                                    if (mi2.getOpcode() == RETURN)
                                        break;

                                    //if (classNode.name.contains("WebhookMenu"))
                                    //    System.out.println(prettyprint(mi2));

                                    li2.remove();
                                    //clinitMethod.instructions.remove(mi2);
                                }

//                                if (classNode.name.contains("Resync")) {
//                                    System.out.println(clinitMethod.instructions.size());
//                                    for (AbstractInsnNode i : clinitMethod.instructions.toArray())
//                                        System.out.println(prettyprint(i));
//                                }

                                System.out.println("[BranchLock] [StringEncryptionTransformer] Attempting to grab string pool from " + branchlockStringPool.owner);
                                MethodExecutor.execute(classNode, clinitMethod, Collections.emptyList(), null, context);
                                gotStrings = true;
                                clinitMethod.instructions = clinitInsnList;
                            }

                            if (!gotStrings)
                            {
                                System.out.println("[Branchlock] [StringEncryptionTransformer] Failed getting strings on " + classNode.name);
                                return false;
                            }

                            final ArrayList<AbstractInsnNode> instructions = getInstructionsToEmulate(instruction);
                            if (instructions == null)
                                continue;

                            try {
                                final MethodNode decryptorMethod = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, methodNode.name, "()Ljava/lang/String;", null, null);
                                for (AbstractInsnNode insn : instructions) {
                                    if (classNode.name.contains("WebhookMenu"))
                                        System.out.println(prettyprint(insn));
                                    decryptorMethod.instructions.add(copy(insn));
                                }

                               decryptorMethod.instructions.add(new InsnNode(ARETURN));

                               // for (AbstractInsnNode insn : decryptorMethod.instructions)
                               //     System.out.println(prettyprint(insn));
                               //
                               // System.out.println("-----------------");

                                final String result = MethodExecutor.execute(classNode, decryptorMethod, Collections.emptyList(), null, context);
                                System.out.println("[Branchlock] [StringEncryptionTransformer] Decrypted: " + result);
                                methodNode.instructions.insert(instruction, new LdcInsnNode(result));
                                //for (AbstractInsnNode insn : decryptorMethod.instructions)
                                //    methodNode.instructions.remove(insn);
                                instructions.forEach(insnNode -> methodNode.instructions.remove(insnNode));
                                decryptedCount++;
                            } catch (Throwable e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
        }

        System.out.println("[Branchlock] [StringEncryptionTransformer] Decrypted " + decryptedCount + " strings.");

        return true;
    }

    // too lazy
    private static InsnList copy(InsnList insnList) {
        MethodNode mv = new MethodNode();
        insnList.accept(mv);
        return mv.instructions;
    }

    private static AbstractInsnNode copy(AbstractInsnNode insn) {
        MethodNode mv = new MethodNode();
        insn.accept(mv);
        return mv.instructions.getFirst();
    }

    private ArrayList<AbstractInsnNode> getInstructionsToEmulate(AbstractInsnNode instruction) {
        final ArrayList<AbstractInsnNode> instructions = new ArrayList<AbstractInsnNode>();
        while (instruction != null && instruction.getOpcode() != AALOAD) {
            //System.out.println(prettyprint(instruction));
            instructions.add(instruction);
            instruction = instruction.getNext();
        }

        if (instruction == null)
            return null;

        instructions.add(instruction);
        //System.out.println(prettyprint(instruction) + "\n------------------\n");
        return instructions;
    }

    private FieldInsnNode getBranchlockStringPool(final ClassNode classNode) {
        final Optional<MethodNode> staticBlockOptional = classNode.methods.stream().filter(methodNode -> methodNode.name.equals("<clinit>")).findFirst();
        if (!staticBlockOptional.isPresent())
            return null;

        final MethodNode staticBlock = staticBlockOptional.get();
        boolean hasStracktrace = false;
        for (final AbstractInsnNode instruction : staticBlock.instructions) {
            if (!hasStracktrace && instruction instanceof MethodInsnNode) {
                final MethodInsnNode methodInstruction = (MethodInsnNode) instruction;
                if (methodInstruction.owner.equals("java/lang/StackTraceElement") && methodInstruction.name.equals("getMethodName")) {
                    hasStracktrace = true;
                }
            }
            else if (instruction instanceof FieldInsnNode && instruction.getOpcode() == PUTSTATIC) {
                final FieldInsnNode fieldInstruction = (FieldInsnNode) instruction;
                if (fieldInstruction.desc.equals("[Ljava/lang/String;"))
                    return fieldInstruction;
            }
        }
        return null;
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